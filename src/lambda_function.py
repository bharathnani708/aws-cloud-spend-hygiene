"""AWS cloud spend hygiene audit (READ-ONLY).

Scans every enabled region (or the ones you choose) for idle and orphaned resources that keep
billing after they stop being useful, and emails a report grouped by region through SES
(or SNS as plain text). Optionally writes CSVs to S3. It never modifies or deletes anything.
"""
import csv
import io
import json
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from html import escape

import boto3
from botocore.config import Config

log = logging.getLogger()
log.setLevel(logging.INFO)

# ---------------------------------------------------------------- settings
BUCKET = os.environ.get("REPORT_BUCKET", "")  # optional: empty = email-only mode
TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")                 # plain-text fallback
SES_FROM = os.environ.get("SES_FROM", "")                       # verified sender (HTML email)
SES_TO = [a.strip() for a in os.environ.get("SES_TO", "").split(",") if a.strip()]
SES_REGION = os.environ.get("SES_REGION", "")                   # default: Lambda's own region
MAX_ROWS = int(os.environ.get("MAX_ROWS", "0"))                 # 0 = list every finding
HARD_ROW_CAP = 5000   # keeps the HTML email well under SES's 10 MB message limit
SHOW_SPEND = os.environ.get("SHOW_SPEND", "false").lower() == "true"  # last-month charges section
MIN_AGE_DAYS = int(os.environ.get("MIN_AGE_DAYS", "90"))        # snapshots, AMIs, backups
STOPPED_DAYS = int(os.environ.get("STOPPED_DAYS", "30"))        # stopped EC2 instances
LOOKBACK_DAYS = int(os.environ.get("IDLE_LOOKBACK_DAYS", "14"))  # NAT gateway traffic check
EXCLUDE_KEY = os.environ.get("EXCLUDE_TAG_KEY", "keep")
EXCLUDE_VALUE = os.environ.get("EXCLUDE_TAG_VALUE", "true").lower()

# ---------------------------------------------------------------- pricing
# Every rate is looked up for the resource's OWN region from the AWS Price List API
# (pricing:GetProducts), cached for the run. Order of preference for each rate:
#   1. your override        PRICES_JSON / REGION_PRICES_JSON environment variables
#   2. AWS Price List API   (on-demand list price for that region)
#   3. fallback table       built-in us-east-1 prices (clearly labelled "approx")
# Monthly = hourly rate x 730 hours.
HOURS = 730
USE_PRICING_API = os.environ.get("USE_PRICING_API", "true").lower() == "true"
OVERRIDES = json.loads(os.environ.get("PRICES_JSON", "{}"))               # {"snapshot_gb": 0.055}
REGION_OVERRIDES = json.loads(os.environ.get("REGION_PRICES_JSON", "{}"))  # {"eu-west-1": {...}}

FALLBACK = {  # us-east-1 list prices (USD), used only when the API has no answer
    "snapshot_gb": 0.05, "snapshot_archive_gb": 0.0125,
    "rds_snapshot_gb": 0.095, "aurora_snapshot_gb": 0.021,
    "nat_hour": 0.045, "lb_hour_application": 0.0225, "lb_hour_network": 0.0225,
    "eip_hour": 0.005, "ipv4_inuse_hour": 0.005,
    "ebs_iops_io1": 0.065, "ebs_iops_io2": 0.065, "ebs_iops_gp3": 0.005, "ebs_tput_gp3": 0.04,
    "ebs_gb:gp3": 0.08, "ebs_gb:gp2": 0.10, "ebs_gb:io1": 0.125, "ebs_gb:io2": 0.125,
    "ebs_gb:st1": 0.045, "ebs_gb:sc1": 0.015, "ebs_gb:standard": 0.05,
}
# Optional: rates you have confirmed against your own bills, e.g. {"ca-central-1": {"aurora_snapshot_gb": 0.023}}
FALLBACK_VERIFIED = {}

# key -> (Price List service code, extra filters, usagetype to match, unit)
QUERIES = {
    "snapshot_gb":         ("AmazonEC2", {"productFamily": "Storage Snapshot"}, "EBS:SnapshotUsage", "GB-Mo"),
    "snapshot_archive_gb": ("AmazonEC2", {"productFamily": "Storage Snapshot"}, "EBS:SnapshotArchiveStorage", "GB-Mo"),
    "rds_snapshot_gb":     ("AmazonRDS", {"productFamily": "Storage Snapshot"}, "RDS:ChargedBackupUsage", "GB-Mo"),
    "aurora_snapshot_gb":  ("AmazonRDS", {"productFamily": "Storage Snapshot"}, "Aurora:BackupUsage", "GB-Mo"),
    "nat_hour":            ("AmazonEC2", {"productFamily": "NAT Gateway"}, "NatGateway-Hours", "Hrs"),
    "lb_hour_application": ("AWSELB", {"productFamily": "Load Balancer-Application"}, "LoadBalancerUsage", "Hrs"),
    "lb_hour_network":     ("AWSELB", {"productFamily": "Load Balancer-Network"}, "LoadBalancerUsage", "Hrs"),
    "eip_hour":            ("AmazonVPC", {}, "PublicIPv4:IdleAddress", "Hrs"),
    "ipv4_inuse_hour":     ("AmazonVPC", {}, "PublicIPv4:InUseAddress", "Hrs"),
    "ebs_iops_io1":        ("AmazonEC2", {"productFamily": "System Operation", "volumeApiName": "io1"},
                            "EBS:VolumeP-IOPS.piops", "IOPS-Mo"),
    "ebs_iops_io2":        ("AmazonEC2", {"productFamily": "System Operation", "volumeApiName": "io2"},
                            "EBS:VolumeP-IOPS.io2", "IOPS-Mo"),
    "ebs_iops_gp3":        ("AmazonEC2", {"productFamily": "System Operation", "volumeApiName": "gp3"},
                            "EBS:VolumeP-IOPS.gp3", "IOPS-Mo"),
    "ebs_tput_gp3":        ("AmazonEC2", {"productFamily": "Provisioned Throughput", "volumeApiName": "gp3"},
                            "EBS:VolumeP-Throughput.gp3", "GiBps-mo"),
}
EBS_TYPES = ("gp3", "gp2", "io1", "io2", "st1", "sc1", "standard")

# AWS Backup recovery points: use the rate of the underlying service where one exists.
BACKUP_KEY = {"EBS": "snapshot_gb", "EC2": "snapshot_gb", "RDS": "rds_snapshot_gb",
              "Aurora": "aurora_snapshot_gb", "DocumentDB": "aurora_snapshot_gb",
              "Neptune": "aurora_snapshot_gb"}
BACKUP_APPROX = {"EFS": 0.05, "S3": 0.05, "DynamoDB": 0.10, "FSx": 0.05}  # us-east-1 warm storage

_lock = threading.Lock()
_cache = {}
_pricing_client = None
_REGION_PREFIX = re.compile(r"^[A-Z]{2,4}\d?-")   # usagetype prefixes such as CAN1-, USE1-, EUW1-


def _api():
    global _pricing_client
    with _lock:
        if _pricing_client is None:  # the Price List API is served from us-east-1
            _pricing_client = boto3.client(
                "pricing", region_name="us-east-1",
                config=Config(retries={"max_attempts": 10, "mode": "adaptive"}))
    return _pricing_client


def _from_api(region, key):
    if key.startswith("ebs_gb:"):
        service, extra, wanted, unit = ("AmazonEC2", {"productFamily": "Storage",
                                        "volumeApiName": key.split(":", 1)[1]},
                                        "EBS:VolumeUsage", "GB-Mo")
    else:
        service, extra, wanted, unit = QUERIES[key]
    filters = [{"Type": "TERM_MATCH", "Field": "regionCode", "Value": region}]
    filters += [{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in extra.items()]
    for page in _api().get_paginator("get_products").paginate(ServiceCode=service, Filters=filters):
        for raw in page["PriceList"]:
            product = json.loads(raw)
            usage = _REGION_PREFIX.sub("", product["product"]["attributes"].get("usagetype", ""))
            if not (usage.startswith(wanted) if key.startswith("ebs_gb:") else usage == wanted):
                continue
            for term in product.get("terms", {}).get("OnDemand", {}).values():
                dims = sorted(term["priceDimensions"].values(),
                              key=lambda d: float(d.get("beginRange") or 0))
                for d in dims:
                    usd = float(d["pricePerUnit"].get("USD", 0))
                    if usd > 0 and d.get("unit") == unit:
                        return usd / 1024 if key == "ebs_tput_gp3" else usd  # API quotes GiBps; we use MiBps
    return None


def rate(region, key):
    """(usd, source) for one price key in one region."""
    ck = (region, key)
    with _lock:
        if ck in _cache:
            return _cache[ck]
    found = None
    override = REGION_OVERRIDES.get(region, {}).get(key, OVERRIDES.get(key))
    if override is not None:
        found = (float(override), "your override")
    elif USE_PRICING_API:
        try:
            usd = _from_api(region, key)
            if usd:
                found = (usd, "AWS API")
        except Exception as e:
            log.warning("pricing lookup %s %s failed: %s", region, key, e)
    if found is None:
        verified = FALLBACK_VERIFIED.get(region, {}).get(key)
        if verified is not None:
            found = (verified, "CUR-verified")
        else:
            default = 0.10 if key.startswith("ebs_gb:") else 0.0
            found = (FALLBACK.get(key, default), "approx (us-east-1)")
    with _lock:
        _cache[ck] = found
    return found


def gb_cost(region, key, gb, note=""):
    usd, src = rate(region, key)
    return gb * usd, f"{gb:g} GB x ${usd:.4g}/GB-mo [{src}]{note}"


def hour_cost(region, key, note=""):
    usd, src = rate(region, key)
    return usd * HOURS, f"${usd:.4g}/hr x {HOURS}h [{src}]{note}"


def price_check(regions):
    """Resolve every rate for the given regions so you can compare them with your bills."""
    keys = list(QUERIES) + [f"ebs_gb:{t}" for t in EBS_TYPES]
    table = {}
    for region in regions:
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda k: rate(region, k), keys))
        table[region] = {k: f"{usd:.5g}  [{src}]" for k, (usd, src) in zip(keys, results)}
    return table


FIELDS = ["region", "resource_type", "resource_id", "name", "created", "age_days",
          "size_gb", "confidence", "evidence", "est_monthly_cost_usd", "cost_basis",
          "recommendation"]

UPPER = " - upper bound (snapshots are incremental)"


# ----------------------------------------------------------------- helpers
def now():
    return datetime.now(timezone.utc)


def age_days(dt):
    return (now() - dt).days


def parse_iso(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def tag_dict(tags):
    return {t["Key"]: t.get("Value", "") for t in (tags or [])}


def excluded(tags):
    return tag_dict(tags).get(EXCLUDE_KEY, "").lower() == EXCLUDE_VALUE


def name_of(tags):
    return tag_dict(tags).get("Name", "")


def finding(region, rtype, rid, *, name="", created=None, size_gb=None, confidence,
            evidence, cost, basis, rec, cur_ids=None, cur_extra=0.0):
    return {
        "_cur_ids": list(cur_ids or []),   # resource IDs to look up in CUR; removed before output
        "_cur_extra": cur_extra,           # estimated part CUR does not attribute to those IDs (public IPv4)
        "region": region, "resource_type": rtype, "resource_id": rid, "name": name,
        "created": created.strftime("%Y-%m-%d") if created else "",
        "age_days": age_days(created) if created else "",
        "size_gb": size_gb if size_gb is not None else "",
        "confidence": confidence, "evidence": evidence,
        "est_monthly_cost_usd": round(cost, 2), "cost_basis": basis,
        "recommendation": rec,
    }


def vol_cost(region, v):
    """Storage + provisioned performance (io1/io2 IOPS; gp3 IOPS above 3000 and MiB/s above 125)."""
    vt = v["VolumeType"]
    cost, basis = gb_cost(region, f"ebs_gb:{vt}", v["Size"])
    extra = []
    iops, tput = v.get("Iops") or 0, v.get("Throughput") or 0
    if vt in ("io1", "io2") and iops:
        usd, src = rate(region, f"ebs_iops_{vt}")
        cost += iops * usd
        extra.append(f"{iops} IOPS x ${usd:.4g} [{src}]" + ("; io2 tier discounts above 32k IOPS ignored"
                                                          if vt == "io2" and iops > 32000 else ""))
    if vt == "gp3":
        if iops > 3000:
            usd, src = rate(region, "ebs_iops_gp3")
            cost += (iops - 3000) * usd
            extra.append(f"{iops - 3000} extra IOPS x ${usd:.4g} [{src}]")
        if tput > 125:
            usd, src = rate(region, "ebs_tput_gp3")
            cost += (tput - 125) * usd
            extra.append(f"{tput - 125} extra MiB/s x ${usd:.4g} [{src}]")
    return cost, basis + ("; + " + "; + ".join(extra) if extra else "")


def last_launched(ec2, image_id):
    try:
        r = ec2.describe_image_attribute(ImageId=image_id, Attribute="lastLaunchedTime")
        val = r.get("LastLaunchedTime", {}).get("Value")
        return parse_iso(val) if val else None
    except Exception:
        return None


# ------------------------------------------------------------ EC2 / EBS
def snap_gb(s):
    """Data actually held by a snapshot (full size, GiB) when AWS reports it, else the volume size.
    Billing is on the incremental data, so this is still an upper bound, but tighter than VolumeSize."""
    full = s.get("FullSnapshotSizeInBytes")
    return round(full / 2**30, 3) if full else s.get("VolumeSize", 0)


def scan_ec2(region, cfg):
    ec2 = boto3.client("ec2", region_name=region, config=cfg)
    out = []

    volumes = {}
    for page in ec2.get_paginator("describe_volumes").paginate():
        for v in page["Volumes"]:
            volumes[v["VolumeId"]] = v

    used_amis, stopped = set(), []
    for page in ec2.get_paginator("describe_instances").paginate():
        for res in page["Reservations"]:
            for i in res["Instances"]:
                used_amis.add(i.get("ImageId"))
                if i["State"]["Name"] == "stopped":
                    stopped.append(i)

    # AMIs referenced by launch templates (all versions) and launch configurations
    for page in ec2.get_paginator("describe_launch_templates").paginate():
        for lt in page["LaunchTemplates"]:
            pager = ec2.get_paginator("describe_launch_template_versions")
            for vp in pager.paginate(LaunchTemplateId=lt["LaunchTemplateId"]):
                for ver in vp["LaunchTemplateVersions"]:
                    ami = ver["LaunchTemplateData"].get("ImageId")
                    if ami:
                        used_amis.add(ami)
    try:
        asg = boto3.client("autoscaling", region_name=region, config=cfg)
        for page in asg.get_paginator("describe_launch_configurations").paginate():
            for lc in page["LaunchConfigurations"]:
                used_amis.add(lc["ImageId"])
    except Exception as e:
        log.warning("%s autoscaling: %s", region, e)

    snapshots = [s for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"])
                 for s in page["Snapshots"]]
    snap_size = {s["SnapshotId"]: snap_gb(s) for s in snapshots}

    # --- AMIs
    images = ec2.describe_images(Owners=["self"])["Images"]
    snap_to_amis = {}
    for img in images:
        for m in img.get("BlockDeviceMappings", []):
            sid = m.get("Ebs", {}).get("SnapshotId")
            if sid:
                snap_to_amis.setdefault(sid, []).append(img["ImageId"])

    for img in images:
        iid = img["ImageId"]
        created = parse_iso(img["CreationDate"])
        if excluded(img.get("Tags")) or age_days(created) < MIN_AGE_DAYS or iid in used_amis:
            continue
        last = last_launched(ec2, iid)
        if last and age_days(last) < MIN_AGE_DAYS:
            continue
        snaps = [(m["Ebs"]["SnapshotId"],
                  snap_size.get(m["Ebs"]["SnapshotId"], m["Ebs"].get("VolumeSize", 0)))
                 for m in img.get("BlockDeviceMappings", [])
                 if m.get("Ebs", {}).get("SnapshotId")]
        size = sum(s for _, s in snaps)
        ev = ("No instance, launch template or launch config uses it; "
              + (f"last launched {last:%Y-%m-%d}" if last else "no launch recorded")
              + ". Use by other accounts not checked.")
        ami_cost, ami_basis = gb_cost(region, "snapshot_gb", size, UPPER)
        out.append(finding(
            region, "AMI", iid, name=img.get("Name", ""), created=created, size_gb=size,
            confidence="MEDIUM", evidence=ev, cost=ami_cost,
            basis=ami_basis, cur_ids=[s for s, _ in snaps],
            rec="Deprecate, wait, deregister, then delete snapshots: "
                + " ".join(s for s, _ in snaps)))

    # --- Snapshots (those backing an AMI are covered by the AMI rows above)
    if True:
        for s in snapshots:
            sid = s["SnapshotId"]
            tags = s.get("Tags")
            created = s["StartTime"]
            if sid in snap_to_amis or excluded(tags) or age_days(created) < MIN_AGE_DAYS:
                continue
            if any(k.startswith("aws:backup") for k in tag_dict(tags)):
                continue  # managed by AWS Backup, reviewed in the Backup section
            vol_alive = s.get("VolumeId") in volumes
            snap_cost, snap_basis = gb_cost(
                region, "snapshot_archive_gb" if s.get("StorageTier") == "archive" else "snapshot_gb",
                snap_gb(s), UPPER)
            if vol_alive:
                conf, ev = "MEDIUM", "Source volume still exists; snapshot is old"
                rec = "Keep the newest few, delete older redundant ones"
            else:
                conf, ev = "HIGH", "Source volume deleted and no AMI references this snapshot"
                rec = "Likely orphaned: review and delete"
            out.append(finding(
                region, "EBS snapshot", sid,
                name=name_of(tags) or s.get("Description", "")[:60], created=created,
                size_gb=snap_gb(s), confidence=conf, evidence=ev,
                cost=snap_cost, basis=snap_basis, rec=rec, cur_ids=[sid]))

    # --- Unattached volumes
    for vid, v in volumes.items():
        if v["State"] != "available" or excluded(v.get("Tags")) \
                or age_days(v["CreateTime"]) < 7:
            continue
        v_cost, v_basis = vol_cost(region, v)
        out.append(finding(
            region, "EBS volume (unattached)", vid, name=name_of(v.get("Tags")),
            created=v["CreateTime"], size_gb=v["Size"], confidence="HIGH",
            evidence=f"State 'available' (not attached), type {v['VolumeType']}",
            cost=v_cost, basis=v_basis, cur_ids=[vid],
            rec="Snapshot if needed, then delete"))

    addresses = ec2.describe_addresses()["Addresses"]

    # --- Long-stopped instances
    for i in stopped:
        if excluded(i.get("Tags")):
            continue
        m = re.search(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)",
                      i.get("StateTransitionReason", ""))
        if not m:
            continue
        since = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        if age_days(since) < STOPPED_DAYS:
            continue
        iid = i["InstanceId"]
        attached = [v for v in volumes.values()
                    if any(a.get("InstanceId") == iid for a in v.get("Attachments", []))]
        vcosts = [vol_cost(region, v) for v in attached]
        i_basis = ("attached EBS volumes: " + " | ".join(b for _, b in vcosts)
                   if vcosts else "no attached EBS volumes")
        # An Elastic IP still associated with a stopped instance keeps billing as in-use IPv4.
        eips = [a for a in addresses if a.get("InstanceId") == iid]
        ip_cost = 0.0
        if eips:
            usd, src = rate(region, "ipv4_inuse_hour")
            ip_cost = len(eips) * usd * HOURS
            i_basis += f" | {len(eips)} Elastic IP x ${usd:.4g}/hr x {HOURS}h [{src}]"
        out.append(finding(
            region, "EC2 instance (stopped)", iid, name=name_of(i.get("Tags")),
            created=since, size_gb=sum(v["Size"] for v in attached), confidence="MEDIUM",
            evidence=f"Stopped since {since:%Y-%m-%d}; its EBS volumes still bill "
                     f"(age_days = days stopped)",
            cost=sum(c for c, _ in vcosts) + ip_cost, basis=i_basis,
            cur_ids=[v["VolumeId"] for v in attached], cur_extra=ip_cost,
            rec="Create AMI/snapshot if needed, then terminate"))

    # --- Elastic IPs
    for a in addresses:
        if "AssociationId" in a or excluded(a.get("Tags")):
            continue
        eip_cost, eip_basis = hour_cost(region, "eip_hour", "; idle public IPv4")
        out.append(finding(
            region, "Elastic IP (unassociated)", a.get("AllocationId", a.get("PublicIp")),
            name=a.get("PublicIp", ""), confidence="HIGH",
            evidence="Allocated but not associated with anything",
            cost=eip_cost, basis=eip_basis, rec="Release"))
    return out


# --------------------------------------------------------------- NAT / LB
def scan_nat(region, cfg):
    ec2 = boto3.client("ec2", region_name=region, config=cfg)
    cw = boto3.client("cloudwatch", region_name=region, config=cfg)
    out = []
    for page in ec2.get_paginator("describe_nat_gateways").paginate(
            Filter=[{"Name": "state", "Values": ["available"]}]):
        for n in page["NatGateways"]:
            created = n["CreateTime"]
            if excluded(n.get("Tags")) or age_days(created) < LOOKBACK_DAYS:
                continue
            stats = cw.get_metric_statistics(
                Namespace="AWS/NATGateway", MetricName="BytesOutToDestination",
                Dimensions=[{"Name": "NatGatewayId", "Value": n["NatGatewayId"]}],
                StartTime=now() - timedelta(days=LOOKBACK_DAYS), EndTime=now(),
                Period=86400, Statistics=["Sum"])
            if sum(p["Sum"] for p in stats["Datapoints"]) > 0:
                continue
            nat_cost, nat_basis = hour_cost(region, "nat_hour", "; hourly only, excl. data processing")
            n_ip = sum(1 for a in n.get("NatGatewayAddresses", []) if a.get("PublicIp"))
            ip_cost = 0.0
            if n_ip:  # each public NAT gateway also holds a billable public IPv4 address
                usd, src = rate(region, "ipv4_inuse_hour")
                ip_cost = n_ip * usd * HOURS
                nat_basis += f"; + {n_ip} public IPv4 x ${usd:.4g}/hr x {HOURS}h [{src}]"
            out.append(finding(
                region, "NAT gateway (idle)", n["NatGatewayId"], name=name_of(n.get("Tags")),
                created=created, confidence="HIGH",
                evidence=f"Zero bytes sent in the last {LOOKBACK_DAYS} days",
                cost=nat_cost + ip_cost, basis=nat_basis, rec="Delete and update routes",
                cur_ids=[n["NatGatewayId"]], cur_extra=ip_cost))
    return out


def scan_elb(region, cfg):
    elb = boto3.client("elbv2", region_name=region, config=cfg)
    out = []
    for page in elb.get_paginator("describe_load_balancers").paginate():
        for lb in page["LoadBalancers"]:
            if lb["Type"] not in ("application", "network"):
                continue
            arn, created = lb["LoadBalancerArn"], lb["CreatedTime"]
            if age_days(created) < 7:
                continue
            tags = elb.describe_tags(ResourceArns=[arn])["TagDescriptions"][0]["Tags"]
            if excluded(tags):
                continue
            registered = 0
            for tg in elb.describe_target_groups(LoadBalancerArn=arn)["TargetGroups"]:
                registered += len(elb.describe_target_health(
                    TargetGroupArn=tg["TargetGroupArn"])["TargetHealthDescriptions"])
            if registered:
                continue
            lb_cost, lb_basis = hour_cost(region, f"lb_hour_{lb['Type']}", "; base hourly only, excl. LCU")
            ip_cost = 0.0
            if lb.get("Scheme") == "internet-facing":  # one public IPv4 per Availability Zone
                n_az = len(lb.get("AvailabilityZones", []))
                usd, src = rate(region, "ipv4_inuse_hour")
                ip_cost = n_az * usd * HOURS
                lb_basis += f"; + {n_az} public IPv4 (1 per AZ) x ${usd:.4g}/hr x {HOURS}h [{src}]"
            out.append(finding(
                region, f"Load balancer ({lb['Type']}, idle)", lb["LoadBalancerName"],
                created=created, confidence="MEDIUM",
                evidence="No targets registered in any target group "
                         "(check it is not a redirect-only ALB)",
                cost=lb_cost + ip_cost, basis=lb_basis, rec="Review and delete",
                cur_ids=[arn], cur_extra=ip_cost))
    return out


# -------------------------------------------------------- RDS / AWS Backup
def scan_rds(region, cfg):
    rds = boto3.client("rds", region_name=region, config=cfg)
    out = []
    instances = set()
    for page in rds.get_paginator("describe_db_instances").paginate():
        instances.update(d["DBInstanceIdentifier"] for d in page["DBInstances"])
    for page in rds.get_paginator("describe_db_snapshots").paginate(SnapshotType="manual"):
        for s in page["DBSnapshots"]:
            created = s.get("SnapshotCreateTime")
            if not created or age_days(created) < MIN_AGE_DAYS or excluded(s.get("TagList")):
                continue
            alive = s["DBInstanceIdentifier"] in instances
            rds_cost, rds_basis = gb_cost(region, "rds_snapshot_gb", s["AllocatedStorage"])
            out.append(finding(
                region, "RDS manual snapshot", s["DBSnapshotIdentifier"], created=created,
                size_gb=s["AllocatedStorage"], confidence="MEDIUM" if alive else "HIGH",
                evidence="Source DB still exists" if alive else "Source DB instance deleted",
                cost=rds_cost, basis=rds_basis, cur_ids=[s.get("DBSnapshotArn", "")],
                rec="Review and delete if not needed for compliance"))
    for page in rds.get_paginator("describe_db_cluster_snapshots").paginate(SnapshotType="manual"):
        for s in page["DBClusterSnapshots"]:
            created = s.get("SnapshotCreateTime")
            if not created or age_days(created) < MIN_AGE_DAYS or excluded(s.get("TagList")):
                continue
            aurora = s.get("Engine", "").startswith("aurora")
            cl_cost, cl_basis = gb_cost(
                region, "aurora_snapshot_gb" if aurora else "rds_snapshot_gb", s["AllocatedStorage"])
            out.append(finding(
                region, "RDS cluster snapshot", s["DBClusterSnapshotIdentifier"],
                created=created, size_gb=s["AllocatedStorage"], confidence="MEDIUM",
                evidence=f"Manual snapshot of cluster {s['DBClusterIdentifier']}",
                cost=cl_cost, basis=cl_basis, cur_ids=[s.get("DBClusterSnapshotArn", "")],
                rec="Review and delete if not needed"))
    return out


def scan_backup(region, cfg):
    bk = boto3.client("backup", region_name=region, config=cfg)
    out = []
    for vp in bk.get_paginator("list_backup_vaults").paginate():
        for vault in vp["BackupVaultList"]:
            vname = vault["BackupVaultName"]
            for rp in bk.get_paginator("list_recovery_points_by_backup_vault").paginate(
                    BackupVaultName=vname):
                for r in rp["RecoveryPoints"]:
                    created = r["CreationDate"]
                    if r.get("Status") != "COMPLETED" or age_days(created) < MIN_AGE_DAYS:
                        continue
                    if r.get("CalculatedLifecycle", {}).get("DeleteAt"):
                        continue  # has an expiry, so it will clean itself up
                    gb = (r.get("BackupSizeInBytes") or 0) / 2**30  # AWS bills GiB
                    rtype = r.get("ResourceType", "")
                    if rtype in BACKUP_KEY:
                        b_cost, b_basis = gb_cost(region, BACKUP_KEY[rtype], gb,
                                                  f"; {rtype} rate" + UPPER)
                    else:  # no direct API mapping: us-east-1 warm-storage rate, clearly labelled
                        usd = BACKUP_APPROX.get(rtype, 0.05)
                        b_cost = gb * usd
                        b_basis = f"{gb:.4g} GB x ${usd}/GB-mo [approx (us-east-1)]; {rtype}" + UPPER
                    out.append(finding(
                        region, "AWS Backup recovery point", r["RecoveryPointArn"].split(":")[-1],
                        name=f"{vname} / {r['ResourceType']}", created=created,
                        size_gb=round(gb, 2), confidence="MEDIUM",
                        evidence="No expiry set, so it is kept forever",
                        cost=b_cost, basis=b_basis, cur_ids=[r["RecoveryPointArn"]],
                        rec="Add a lifecycle/retention rule or delete manually"))
    return out


# ---------------------------------------------------------- orchestration
SCANNERS = (scan_ec2, scan_nat, scan_elb, scan_rds, scan_backup)


def scan_region(region):
    cfg = Config(retries={"max_attempts": 10, "mode": "adaptive"})
    rows, errors = [], []
    for fn in SCANNERS:
        try:
            rows += fn(region, cfg)
        except Exception as e:  # keep going: one denied API must not kill the report
            log.warning("%s %s failed: %s", region, fn.__name__, e)
            errors.append(f"{region} {fn.__name__}: {type(e).__name__}: {e}"[:300])
    return rows, errors


def cost_by_usage_type():
    """Last full month's spend on the usage types that relate to these resources."""
    ce = boto3.client("ce", region_name="us-east-1")
    first_this = now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    start = (first_this - timedelta(days=1)).replace(day=1)
    services = ["EC2 - Other", "Amazon Elastic Compute Cloud - Compute",
                "Amazon Relational Database Service", "AWS Backup",
                "Amazon Elastic Load Balancing", "Amazon Virtual Private Cloud"]
    keywords = ("Snapshot", "EBS:", "ElasticIP", "NatGateway", "LoadBalancer",
                "PublicIPv4", "Backup", "WarmStorage", "ColdStorage")
    rows, token = [], None
    while True:
        kw = dict(
            TimePeriod={"Start": start.strftime("%Y-%m-%d"), "End": first_this.strftime("%Y-%m-%d")},
            Granularity="MONTHLY", Metrics=["UnblendedCost"],
            Filter={"Dimensions": {"Key": "SERVICE", "Values": services}},
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"},
                     {"Type": "DIMENSION", "Key": "USAGE_TYPE"}])
        if token:
            kw["NextPageToken"] = token
        resp = ce.get_cost_and_usage(**kw)
        for period in resp["ResultsByTime"]:
            for g in period["Groups"]:
                svc, ut = g["Keys"]
                cost = float(g["Metrics"]["UnblendedCost"]["Amount"])
                if cost > 0 and (svc == "AWS Backup" or any(k in ut for k in keywords)):
                    rows.append({"month": start.strftime("%Y-%m"), "service": svc,
                                 "usage_type": ut, "cost_usd": round(cost, 2)})
        token = resp.get("NextPageToken")
        if not token:
            break
    return sorted(rows, key=lambda r: -r["cost_usd"])


# ------------------------------------------------- billed actuals (CUR / Athena)
# Optional. When these are set, each flagged resource's cost is replaced by what AWS actually
# billed for that resource ID last full month (the same numbers as your Athena queries).
CUR_DB = os.environ.get("CUR_DATABASE", "")
CUR_TABLE = os.environ.get("CUR_TABLE", "")
CUR_OUTPUT = os.environ.get("ATHENA_OUTPUT", "")             # s3://bucket/prefix/ for query results
CUR_WORKGROUP = os.environ.get("ATHENA_WORKGROUP", "primary")
CUR_REGION = os.environ.get("ATHENA_REGION", "")             # default: Lambda's own region
CUR_COST_COL = os.environ.get("CUR_COST_COLUMN", "line_item_unblended_cost")
CUR_PARTITION_SQL = os.environ.get("CUR_PARTITION_SQL", "")  # e.g. "AND year='{year}' AND month='{month}'"
CUR_ENABLED = bool(CUR_DB and CUR_TABLE and (CUR_OUTPUT or CUR_WORKGROUP != "primary"))
_SAFE_ID = re.compile(r"^[A-Za-z0-9:/_.\-]+$")


def _cur_month():
    first_this = now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    start = (first_this - timedelta(days=1)).replace(day=1)
    return start, first_this


def cur_actuals(ids):
    """{resource_id: billed USD for last full month} for the IDs that appear in CUR."""
    start, end = _cur_month()
    ath = boto3.client("athena", region_name=CUR_REGION or None,
                       config=Config(retries={"max_attempts": 10, "mode": "adaptive"}))
    part = CUR_PARTITION_SQL.format(year=start.year, month=start.month) if CUR_PARTITION_SQL else ""
    ids = sorted({i for i in ids if i and _SAFE_ID.match(i)})
    out = {}
    for n in range(0, len(ids), 400):
        in_list = ", ".join("'" + i + "'" for i in ids[n:n + 400])
        # CUR writes EBS snapshots as an ARN (arn:aws:ec2:...:snapshot/snap-xxx) but volumes, NAT
        # gateways etc. as bare IDs, so snapshot ARNs are reduced to their snap-xxx ID first.
        sql = (f'SELECT rid, SUM(c) FROM (SELECT COALESCE(NULLIF(regexp_extract('
               f"line_item_resource_id, 'snapshot/(snap-[0-9a-f]+)$', 1), ''), line_item_resource_id) AS rid, "
               f'{CUR_COST_COL} AS c FROM "{CUR_DB}"."{CUR_TABLE}" '
               f"WHERE line_item_usage_start_date >= TIMESTAMP '{start:%Y-%m-%d} 00:00:00' "
               f"AND line_item_usage_start_date < TIMESTAMP '{end:%Y-%m-%d} 00:00:00' "
               f"AND line_item_line_item_type NOT IN ('Tax', 'Credit', 'Refund') {part}) "
               f"WHERE rid IN ({in_list}) GROUP BY 1")
        kw = {"QueryString": sql, "WorkGroup": CUR_WORKGROUP}
        if CUR_OUTPUT:
            kw["ResultConfiguration"] = {"OutputLocation": CUR_OUTPUT}
        qid = ath.start_query_execution(**kw)["QueryExecutionId"]
        while True:
            st = ath.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]
            if st["State"] in ("SUCCEEDED", "FAILED", "CANCELLED"):
                break
            time.sleep(2)
        if st["State"] != "SUCCEEDED":
            raise RuntimeError(f"Athena {st['State']}: {st.get('StateChangeReason', '')}"[:250])
        first = True
        for page in ath.get_paginator("get_query_results").paginate(QueryExecutionId=qid):
            for row in page["ResultSet"]["Rows"]:
                if first:  # header row
                    first = False
                    continue
                cells = [c.get("VarCharValue", "") for c in row["Data"]]
                if cells[0] and cells[1]:
                    out[cells[0]] = float(cells[1])
    return out


def apply_actuals(findings, errors):
    """Replace estimates with CUR billed amounts where CUR has rows for the resource."""
    wanted = [i for f in findings for i in f.get("_cur_ids", [])]
    if not (CUR_ENABLED and wanted):
        return
    start, _ = _cur_month()
    label = f"{start:%Y-%m}"
    try:
        actual = cur_actuals(wanted)
    except Exception as e:
        log.warning("CUR lookup failed: %s", e)
        errors.append(f"CUR/Athena lookup failed, list-price estimates kept: {type(e).__name__}: {e}"[:300])
        return
    month_days = (now() - start).days
    for f in findings:
        ids = f.get("_cur_ids", [])
        if not ids:
            continue
        hit = [actual[i] for i in ids if i in actual]
        age = f.get("age_days")
        new_this_month = (f["resource_type"] != "EC2 instance (stopped)"
                          and isinstance(age, int) and age < month_days)
        est = f["est_monthly_cost_usd"]
        if not hit:
            f["cost_basis"] += f" | no CUR rows for this ID in {label}: estimate kept"
        elif new_this_month:
            f["cost_basis"] += f" | created after {label} began (partial month in CUR): estimate kept"
        else:
            billed = sum(hit)
            extra = f.get("_cur_extra", 0.0)
            f["est_monthly_cost_usd"] = round(billed + extra, 2)
            f["cost_basis"] = (f"CUR billed {label}: ${billed:,.2f} ({len(hit)} of {len(ids)} resource ID(s))"
                               + (f" + est. public IPv4 ${extra:,.2f}" if extra else "")
                               + f" | list-price estimate was ${est:,.2f}")


def approx_price_warnings():
    """Tell the reader when any rate was NOT confirmed by the AWS Price List API."""
    with _lock:
        bad = sorted((r, k) for (r, k), (_, src) in _cache.items() if src.startswith("approx"))
    if not bad:
        return []
    by_region = {}
    for r, k in bad:
        by_region.setdefault(r, []).append(k)
    return [f"Approximate us-east-1 prices were used in {r} for: {', '.join(ks)}. "
            "Check that the role allows pricing:GetProducts; those rows may be off."
            for r, ks in by_region.items()]


def to_csv(rows, fields):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def summarize(findings):
    by_type = {}
    for f in findings:
        t = by_type.setdefault(f["resource_type"], {"count": 0, "cost": 0.0, "high": 0.0})
        t["count"] += 1
        t["cost"] += f["est_monthly_cost_usd"]
        if f["confidence"] == "HIGH":
            t["high"] += f["est_monthly_cost_usd"]
    return by_type


def money(x):
    return f"${x:,.2f}"


# ------------------------------------------------------------- email build
TH = ("background:#f2f4f7;border-bottom:2px solid #d0d5dd;padding:6px 8px;"
      "font-size:12px;white-space:nowrap;")
TD = "border-bottom:1px solid #eaecf0;padding:6px 8px;font-size:12px;vertical-align:top;"
CONF_COLOR = {"HIGH": "#b42318", "MEDIUM": "#b54708"}


def html_table(headers, rows, right_cols=(), bold_last=False, conf_col=None):
    head = "".join(
        f'<th style="{TH}text-align:{"right" if i in right_cols else "left"}">{escape(h)}</th>'
        for i, h in enumerate(headers))
    body = []
    for ri, row in enumerate(rows):
        bold = bold_last and ri == len(rows) - 1
        cells = []
        for ci, val in enumerate(row):
            style = TD + ("text-align:right;" if ci in right_cols else "")
            if bold:
                style += "font-weight:bold;background:#f9fafb;"
            if ci == conf_col and val in CONF_COLOR:
                style += f"color:{CONF_COLOR[val]};font-weight:bold;"
            cells.append(f'<td style="{style}">{escape(str(val))}</td>')
        body.append("<tr>" + "".join(cells) + "</tr>")
    return (f'<table style="border-collapse:collapse;width:100%;margin:6px 0 18px">'
            f"<thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table>")


def text_table(headers, rows, right_cols=()):
    widths = [max(len(str(c)) for c in col) for col in zip(headers, *rows)]

    def fmt(row):
        return " | ".join(str(c).rjust(w) if i in right_cols else str(c).ljust(w)
                          for i, (c, w) in enumerate(zip(row, widths)))
    sep = "-+-".join("-" * w for w in widths)
    return "\n".join([fmt(headers), sep] + [fmt(r) for r in rows])


REPORT_TITLE = os.environ.get("REPORT_TITLE", "AWS Cleanup Review: Unused & Idle Resources")
PURPOSE = ("Resources flagged as possibly unused or idle. Please check each item for your "
           "team and confirm whether it can be removed. Nothing has been deleted.")


# ------------------------------------------------------------- signature
# Optional sign-off at the bottom of the email. Everything is off unless you set it:
#   SIGNATURE_NAME      e.g. "Jane Doe" (leave unset for no signature at all)
#   SIGNATURE_TITLE, SIGNATURE_COMPANY, SIGNATURE_PHONE, SIGNATURE_EMAIL
#   SIGNATURE_NOTE      optional footer text (for example a confidentiality note)
#   SIGNATURE_OOO       e.g. "Oct 20 - Oct 24" -> shows an "Upcoming OOO" line
#   SIGNATURE_LOGO_URL  https:// link to a logo image
SIG_NAME = os.environ.get("SIGNATURE_NAME", "").strip()
SIG_TITLE = os.environ.get("SIGNATURE_TITLE", "").strip()
SIG_COMPANY = os.environ.get("SIGNATURE_COMPANY", "").strip()
SIG_PHONE = os.environ.get("SIGNATURE_PHONE", "").strip()
SIG_EMAIL = os.environ.get("SIGNATURE_EMAIL", "").strip()
SIG_NOTE = os.environ.get("SIGNATURE_NOTE", "").strip()
SIG_OOO = os.environ.get("SIGNATURE_OOO", "").strip()
SIG_LOGO_URL = os.environ.get("SIGNATURE_LOGO_URL", "").strip()


def signature_html():
    if not SIG_NAME:
        return ""
    teal = "color:#1b4b61;"
    font = "font-family:Calibri,Arial,Helvetica,sans-serif;"
    rows = [f'<div style="{font}{teal}font-size:15px;font-weight:bold">{escape(SIG_NAME)}</div>']
    if SIG_TITLE:
        rows.append(f'<div style="{font}{teal}font-size:14px">{escape(SIG_TITLE)}</div>')
    if SIG_COMPANY:
        rows.append(f'<div style="{font}{teal}font-size:14px;margin-top:14px">{escape(SIG_COMPANY)}</div>')
    if SIG_PHONE:
        rows.append(f'<div style="{font}{teal}font-size:14px"><span style="display:inline-block;width:64px">Phone:</span>{escape(SIG_PHONE)}</div>')
    if SIG_EMAIL:
        rows.append(f'<div style="{font}{teal}font-size:14px"><span style="display:inline-block;width:64px">Email:</span>{escape(SIG_EMAIL)}</div>')
    if SIG_OOO:
        rows.append(f'<div style="{font}font-size:12px;font-weight:bold;color:#e5534b;margin-top:14px">'
                    f'Upcoming OOO: <span style="font-weight:normal">{escape(SIG_OOO)}</span></div>')
    if SIG_LOGO_URL.lower().startswith("https://"):   # https only: never data: or javascript: links
        rows.append(f'<div style="margin-top:14px"><img src="{escape(SIG_LOGO_URL)}" alt="{escape(SIG_COMPANY)}" '
                    f'style="max-width:260px;height:auto;border:0"></div>')
    if SIG_NOTE:
        rows.append(f'<div style="{font}font-size:11px;line-height:1.6;color:#1f3864;margin-top:18px">'
                    f'{escape(SIG_NOTE)}</div>')
    return ('<div style="margin-top:28px;padding-top:14px;border-top:1px solid #d0d5dd">'
            + "".join(rows) + "</div>")


def signature_text():
    if not SIG_NAME:
        return ""
    lines = [SIG_NAME] + [x for x in (SIG_TITLE, SIG_COMPANY) if x]
    if SIG_PHONE:
        lines.append(f"Phone: {SIG_PHONE}")
    if SIG_EMAIL:
        lines.append(f"Email: {SIG_EMAIL}")
    if SIG_OOO:
        lines.append(f"Upcoming OOO: {SIG_OOO}")
    if SIG_NOTE:
        lines += ["", SIG_NOTE]
    return "\n".join(lines)



def get_account_id(context):
    """Account ID from the Lambda's own ARN (no API call); STS as a fallback."""
    try:
        return context.invoked_function_arn.split(":")[4]
    except Exception:
        try:
            return boto3.client("sts").get_caller_identity()["Account"]
        except Exception:
            return "unknown"


# Optional team / business-unit labels shown next to each region in the email. Regions listed
# here ALWAYS get a section (in this order); other regions appear only when they have findings.
# Set with an environment variable, e.g.
#   REGION_LABELS_JSON={"us-east-1": "N. Virginia (Platform)", "eu-west-1": "Ireland (Data)"}
REGION_LABELS = {}
REGION_LABELS.update(json.loads(os.environ.get("REGION_LABELS_JSON", "{}")))


def _totals(items):
    cost = sum(f["est_monthly_cost_usd"] for f in items)
    high = sum(f["est_monthly_cost_usd"] for f in items if f["confidence"] == "HIGH")
    return cost, high


def _group_by_region(findings):
    by_region = {}
    for f in findings:
        by_region.setdefault(f["region"], []).append(f)
    order = list(REGION_LABELS) + sorted(r for r in by_region if r not in REGION_LABELS)
    return order, by_region


def _sort_within_region(items):
    """Biggest resource type first, then biggest item first, so each service stays together."""
    type_cost = {}
    for f in items:
        type_cost[f["resource_type"]] = type_cost.get(f["resource_type"], 0) + f["est_monthly_cost_usd"]
    return sorted(items, key=lambda f: (-type_cost[f["resource_type"]], f["resource_type"],
                                        -f["est_monthly_cost_usd"]))


def parse_regions(value):
    """Region choice from the run's event or the REGIONS variable.
    A list or comma-separated text. None means "all enabled regions" (also for [], "all", "*")."""
    if value is None:
        return None
    if isinstance(value, str):
        value = re.split(r"[,\s]+", value.strip())
    value = [str(v).strip().lower() for v in value if str(v).strip()]
    if not value or "all" in value or "*" in value:
        return None
    return list(dict.fromkeys(value))  # drop duplicates, keep order


def scope_text(scanned, n_enabled):
    """(short, long) description of which regions this run covers."""
    if scanned is None or (n_enabled and len(scanned) >= n_enabled):
        return "All regions", (f"All {n_enabled} enabled regions" if n_enabled else "All enabled regions")
    codes = [r for r in REGION_LABELS if r in scanned] + sorted(r for r in scanned if r not in REGION_LABELS)
    named = [f"{REGION_LABELS[r]} ({r})" if REGION_LABELS.get(r, r) != r else r for r in codes]
    if len(codes) == 1:
        short = REGION_LABELS.get(codes[0], codes[0])
    elif len(codes) <= 3:
        short = ", ".join(codes)
    else:
        short = f"{len(codes)} regions"
    long = ", ".join(named) + (f"  ({len(codes)} of {n_enabled} enabled regions)" if n_enabled else "")
    return short, long


def build_email(findings, spend, errors, n_regions, prefix, account_id="", scanned=None, n_enabled=None):
    by_type = summarize(findings)
    total = sum(d["cost"] for d in by_type.values())
    high = sum(d["high"] for d in by_type.values())
    date = f"{now():%Y-%m-%d}"
    # No dollar amounts in the subject: some flagged items may still be needed.
    scope_short, scope_long = scope_text(scanned, n_enabled)
    subject = (f"AWS cleanup review | {scope_short} | {len(findings)} resource{'' if len(findings) == 1 else 's'} to review | "
               f"Account {account_id} | {date}")

    order, by_region = _group_by_region(findings)
    scanned = set(scanned) if scanned is not None else None
    is_all = scanned is None or bool(n_enabled and len(scanned) >= n_enabled)
    if not is_all:  # partial run: show only the regions that were asked for
        order = [r for r in order if r in scanned] + [r for r in sorted(scanned) if r not in order]

    kpi_hdr = ["Regions scanned", "Findings", "Max possible savings / mo (ceiling)",
               "HIGH-confidence savings / mo"]
    kpi_row = [[n_regions if is_all or not n_enabled else f"{n_regions} of {n_enabled}",
                len(findings), money(total), money(high)]]

    reg_hdr = ["Region / Business unit", "Region code", "Items", "Max est. $/mo", "HIGH-confidence $/mo"]
    reg_rows = []
    for r in order:
        c, hc = _totals(by_region.get(r, []))
        reg_rows.append([REGION_LABELS.get(r, r), r, len(by_region.get(r, [])), money(c), money(hc)])
    reg_rows.append(["TOTAL", "", len(findings), money(total), money(high)])

    type_hdr = ["Resource type", "Items", "Max est. $/mo", "HIGH-confidence $/mo"]

    def type_rows_for(items):
        t = summarize(items)
        return [[k, d["count"], money(d["cost"]), money(d["high"])]
                for k, d in sorted(t.items(), key=lambda kv: -kv[1]["cost"])]

    all_type_rows = type_rows_for(findings) + [["TOTAL", len(findings), money(total), money(high)]]

    s_hdr = ["Service", "Usage type", "Last month $"]
    s_rows = [[r["service"], r["usage_type"], money(r["cost_usd"])] for r in spend[:15]]

    note = ("How to read this: the Created date and Age are exact facts from AWS. Dollar figures are "
            "maximum estimates (size x list price for the region), not billed amounts. Snapshot, AMI and "
            "AWS Backup figures are ceilings because AWS bills only the data that changed between "
            "snapshots, so the real saving is often lower. Please decide using age, last use and "
            "ownership, not the dollar amount. Nothing was changed: this report is read-only.")
    where = f"Full CSVs: s3://{BUCKET}/{prefix}" if BUCKET else ""

    # ---- HTML: summary first, then one section per region / team
    h = [f'<div style="font-family:Arial,Helvetica,sans-serif;color:#101828;max-width:1000px">',
         f'<h2 style="margin:0 0 4px">{escape(REPORT_TITLE)}</h2>',
         f'<div style="color:#667085;font-size:12px;margin-bottom:6px">'
         f'Account {escape(account_id)} &middot; {date}</div>',
         f'<p style="font-size:13px;margin:0 0 4px"><b>Scope:</b> {escape(scope_long)}</p>',
         f'<p style="font-size:13px;margin:0 0 14px">{escape(PURPOSE)}</p>',
         html_table(kpi_hdr, kpi_row, right_cols=(0, 1, 2, 3)),
         '<h3 style="margin:14px 0 2px;font-size:14px">Maximum possible savings by region / business unit</h3>',
         html_table(reg_hdr, reg_rows, right_cols=(2, 3, 4), bold_last=True),
         '<h3 style="margin:14px 0 2px;font-size:14px">Maximum possible savings by resource type</h3>',
         html_table(type_hdr, all_type_rows, right_cols=(1, 2, 3), bold_last=True)]

    sec_hdr = ["Type", "Resource", "Created", "Age (days)", "GB", "Conf.", "Max est. $/mo", "Price basis",
               "Why flagged -> action"]
    budget = min(MAX_ROWS or len(findings), HARD_ROW_CAP)
    used = 0
    for r in order:
        items = by_region.get(r, [])
        label = REGION_LABELS.get(r, r)
        code = (f' <span style="color:#667085;font-weight:normal;font-size:12px">{escape(r)}</span>'
                if label != r else "")
        h.append(f'<h3 style="margin:26px 0 4px;padding-top:10px;border-top:2px solid #d0d5dd;'
                 f'font-size:15px">{escape(label)}{code}</h3>')
        if not items:
            msg = ("Not scanned (region not enabled on this account, or excluded)."
                   if scanned is not None and r not in scanned else "No findings in this region.")
            h.append(f'<p style="color:#667085;font-size:12px;margin:2px 0 8px">{msg}</p>')
            continue
        c, hc = _totals(items)
        h.append(f'<div style="font-size:13px;margin:2px 0 8px"><b>{len(items)} item{'' if len(items) == 1 else 's'}</b> &middot; '
                 f'up to <b>{money(c)}/mo</b> &middot; '
                 f'HIGH-confidence <b>{money(hc)}/mo</b></div>')
        h.append(html_table(type_hdr, type_rows_for(items), right_cols=(1, 2, 3)))
        rows = _sort_within_region(items)
        take = rows[:max(0, budget - used)]
        used += len(take)
        if take:
            h.append(html_table(
                sec_hdr,
                [[f["resource_type"], f["resource_id"], f["created"], f["age_days"], f["size_gb"], f["confidence"],
                  money(f["est_monthly_cost_usd"]), f["cost_basis"],
                  f"{f['evidence']} -> {f['recommendation']}"] for f in take],
                right_cols=(3, 4, 6), conf_col=5))
        if len(take) < len(items):
            h.append(f'<p style="color:#b42318;font-size:12px">Showing {len(take)} of {len(items)} '
                     f'rows here (row limit reached; the totals above include every item).</p>')
    if s_rows:
        h += [f'<h3 style="margin:26px 0 2px;font-size:14px">What you were charged last month '
              f'({spend[0]["month"]}), related usage types</h3>',
              html_table(s_hdr, s_rows, right_cols=(2,))]
    if errors:
        h.append('<h3 style="margin:26px 0 2px;font-size:14px;color:#b42318">'
                 f'{len(errors)} scan errors (usually missing permissions)</h3><ul>'
                 + "".join(f'<li style="font-size:12px">{escape(e)}</li>' for e in errors[:10])
                 + "</ul>")
    h.append(f'<p style="color:#667085;font-size:12px">{escape(note)} {escape(where)}</p>')
    h.append(signature_html())
    h.append("</div>")
    html = "".join(h)

    # ---- plain text (fallback / logs): summaries plus the 40 biggest findings
    f_hdr = ["Region", "Type", "Resource", "Created", "Age (days)", "GB", "Conf.", "Max est. $/mo",
             "Price basis", "Why flagged -> action"]
    t = [f"{REPORT_TITLE} - Account {account_id} - {date}", f"Scope: {scope_long}", PURPOSE, "",
         text_table(kpi_hdr, kpi_row, right_cols=(0, 1, 2, 3)), "",
         "Maximum possible savings by region / business unit",
         text_table(reg_hdr, reg_rows, right_cols=(2, 3, 4)), "",
         "Maximum possible savings by resource type",
         text_table(type_hdr, all_type_rows, right_cols=(1, 2, 3))]
    if findings:
        t_rows = [[f["region"], f["resource_type"], f["resource_id"], f["created"], f["age_days"], f["size_gb"],
                   f["confidence"], money(f["est_monthly_cost_usd"]), f["cost_basis"][:60],
                   f"{f['evidence']} -> {f['recommendation']}"[:90]] for f in findings[:40]]
        t += ["", f"Biggest findings (showing {len(t_rows)} of {len(findings)}; "
                  f"the HTML email lists everything by region)",
              text_table(f_hdr, t_rows, right_cols=(4, 5, 7))]
    if s_rows:
        t += ["", f"What you were charged last month ({spend[0]['month']})",
              text_table(s_hdr, s_rows, right_cols=(2,))]
    if errors:
        t += ["", f"{len(errors)} scan errors:"] + [f"  {e}" for e in errors[:10]]
    t += ["", note] + ([where] if where else [])
    if signature_text():
        t += ["", "--", signature_text()]
    return subject, "\n".join(t), html, total, high


def lambda_handler(event, context):
    if isinstance(event, dict) and event.get("price_check"):
        regions = (parse_regions(event.get("regions")) or parse_regions(os.environ.get("REGIONS", ""))
                   or [os.environ.get("AWS_REGION", "us-east-1")])
        table = price_check(regions)
        for region, rows in table.items():
            log.info("PRICE CHECK %s\n%s", region, "\n".join(f"  {k:22} {v}" for k, v in rows.items()))
        return table

    event = event if isinstance(event, dict) else {}
    ec2 = boto3.client("ec2", region_name="us-east-1")
    enabled = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
    # Which regions? The run's event wins ({"regions": [...]}), then the REGIONS variable, else all.
    requested = parse_regions(event["regions"] if "regions" in event else os.environ.get("REGIONS", ""))
    errors = []
    if requested is None:
        regions = enabled
    else:
        regions = [r for r in requested if r in enabled]
        errors += [f"Region '{r}' skipped: not a valid region name, or not enabled on this account"
                   for r in requested if r not in enabled]
        if not regions:
            raise ValueError(f"None of the requested regions are enabled on this account: {requested}")
    log.info("Scanning %d of %d regions: %s", len(regions), len(enabled), ", ".join(regions))

    findings = []
    with ThreadPoolExecutor(max_workers=6) as pool:
        for rows, errs in pool.map(scan_region, regions):
            findings += rows
            errors += errs
    apply_actuals(findings, errors)          # billed amounts from CUR, when configured
    for f in findings:
        f.pop("_cur_ids", None)
        f.pop("_cur_extra", None)
    errors += approx_price_warnings()
    findings.sort(key=lambda r: -r["est_monthly_cost_usd"])

    spend = []
    if SHOW_SPEND:  # optional "what you were charged last month" section
        try:
            spend = cost_by_usage_type()
        except Exception as e:
            errors.append(f"Cost Explorer: {type(e).__name__}: {e}"[:300])

    # ---- optional: full CSVs to S3
    slug = "all" if len(regions) == len(enabled) else "-".join(sorted(regions))[:80]
    prefix = f"reports/{now():%Y-%m-%d}/{slug}/"
    if BUCKET:
        s3 = boto3.client("s3")
        s3.put_object(Bucket=BUCKET, Key=prefix + "findings.csv",
                      Body=to_csv(findings, FIELDS).encode(), ContentType="text/csv")
        s3.put_object(Bucket=BUCKET, Key=prefix + "cost_by_usage_type.csv",
                      Body=to_csv(spend, ["month", "service", "usage_type", "cost_usd"]).encode(),
                      ContentType="text/csv")

    # ---- email: HTML via SES if configured, else plain text via SNS
    subject, text, html, total, high = build_email(
        findings, spend, errors, len(regions), prefix, get_account_id(context), regions, len(enabled))
    log.info(text)
    if SES_FROM and SES_TO:
        ses = boto3.client("ses", region_name=SES_REGION or None)
        ses.send_email(
            Source=SES_FROM, Destination={"ToAddresses": SES_TO},
            Message={"Subject": {"Data": subject, "Charset": "UTF-8"},
                     "Body": {"Text": {"Data": text, "Charset": "UTF-8"},
                              "Html": {"Data": html, "Charset": "UTF-8"}}})
    elif TOPIC_ARN:
        boto3.client("sns").publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=text)

    return {"regions": regions, "findings": len(findings),
            "estimated_monthly_savings_usd": round(total, 2),
            "high_confidence_usd": round(high, 2), "errors": len(errors),
            "s3_prefix": f"s3://{BUCKET}/{prefix}" if BUCKET else ""}
