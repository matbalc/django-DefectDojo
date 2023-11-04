# #  engagements
import logging

from django.db.models.signals import pre_save
from django.dispatch import receiver
from dojo.models import Engagement, Test, Finding, EngagementValidation, ResidualRiskSettings, Product
import dojo.jira_link.helper as jira_helper

logger = logging.getLogger(__name__)


def close_engagement(eng):
    eng.active = False
    eng.status = 'Completed'
    eng.save()

    if jira_helper.get_jira_project(eng):
        jira_helper.close_epic(eng, True)


def reopen_engagement(eng):
    eng.active = True
    eng.status = 'In Progress'
    eng.save()


@receiver(pre_save, sender=Engagement)
def set_name_if_none(sender, instance, *args, **kwargs):
    if not instance.name:
        instance.name = str(instance.target_start)

def validate_engagement(eng):
    def __get_residual_risk_score(rrc, finding):
        engagement = finding.test.engagement
        product = engagement.product
        # from 0 to 5
        if product.business_criticality:
            if product.business_criticality == Product.NONE_CRITICALITY:
                business_criticality_score = 0
            elif product.business_criticality == Product.VERY_LOW_CRITICALITY:
                business_criticality_score = 1
            elif product.business_criticality == Product.LOW_CRITICALITY:
                business_criticality_score = 2
            elif product.business_criticality == Product.MEDIUM_CRITICALITY:
                business_criticality_score = 3
            elif product.business_criticality == Product.HIGH_CRITICALITY:
                business_criticality_score = 4
            elif product.business_criticality == Product.VERY_HIGH_CRITICALITY:
                business_criticality_score = 5
        else:
            # we use medium business criticality as default in case it is not set
            business_criticality_score = 3
        # from 0 to 1
        network_reachability_score = 1 if product.internet_accessible else 0
        # from 0 to 10
        if finding.cvssv3_score:
            cve_score = finding.cvssv3_score
        # If no score available, we base on severity and take worst possible score
        elif finding.severity == "Critical":
            cve_score = 10
        elif finding.severity == "High":
            cve_score = 7.9
        elif finding.severity == "Medium":
            cve_score = 5.9
        elif finding.severity == "Low":
            cve_score = 3.9
        elif finding.severity == "Informational":
            cve_score = 1.9
        # unknown severity is threated as 5. In majority of cases this would mean tolerable finding
        else:
            cve_score = 5.0


        # 100% = bcs + nrs + cve
        bcs_weight = rrc.business_criticality_weight
        nrs_weight = rrc.network_reachability_weight
        cve_weight = rrc.cve_weight
        print(f"Weights: bcs:{bcs_weight:>5} nrs:{nrs_weight:>5} cve:{cve_weight:>5}")
        # from 0 to 10
        # final_score = ((bcs * 2 * bcs_w) / 100) + ((nrc * 10 * nrc_w) / 100) + ((cve * cve_w) / 100)
        final_score = ((business_criticality_score * 2 * bcs_weight) / 100.0) + ((network_reachability_score * 10 * nrs_weight) / 100.0) + ((cve_score * cve_weight) / 100.0)
        # print("test {:<20}".format(finding))
        # print("test {:<20}".format(business_criticality_score))
        # print("test {:<20}".format(network_reachability_score))
        # print("test {:<20}".format(cve_score))
        # print("test {:<20}".format(final_score))
        print("{} bcs:{:>3} nrs:{:>3} cve:{:>3} => final:{:.2}".format(
            finding, business_criticality_score, network_reachability_score, cve_score, final_score
        ))
        finding.residual_risk_level = final_score
        finding.save()
        return final_score
    commit_id = eng.commit_hash
    tests = eng.test_set.all()
    all_findings = []
    for test in tests:
        all_findings += test.finding_set.filter(active=True, is_mitigated=False, risk_accepted=False, out_of_scope=False, false_p=False)
    print(f"DEBUG: amount of relative findings: {len(all_findings)}")
    # for f in all_findings:
    #     print(f"DEBUG: {f}, {f.cvssv3_score}, {f.severity}, {f.cvssv3}, {f.cve}, {f.cwe}")

    # FETCH RESIDUAL RISK CONFIG
    rrc = ResidualRiskSettings.objects.filter(is_default=True).first()

    untolerable_findings = []
    tolerable_findings = []

    if rrc:
        for finding in all_findings:
            residual_score = __get_residual_risk_score(rrc, finding)
            if residual_score >= rrc.tolerance:
                untolerable_findings.append(finding)
            else:
                tolerable_findings.append(finding)
    else:
        tolerable_findings = [finding for finding in all_findings if finding.severity not in ["Critical", "High"]]
        untolerable_findings = list(set(all_findings) - set(tolerable_findings))

    validation = eng.engagementvalidation_set.create(
        valid = len(untolerable_findings) == 0,
    )
    validation.tolerable_findings.set(tolerable_findings)
    validation.untolerable_findings.set(untolerable_findings)

    return validation
