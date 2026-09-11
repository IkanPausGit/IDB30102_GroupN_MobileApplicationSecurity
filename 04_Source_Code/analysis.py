import os
import csv
from androguard.misc import AnalyzeAPK

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE"
}


def add_finding(findings, file_name, package, severity, vulnerability, description):
    findings.append({
        "File": file_name,
        "Package": package,
        "Severity": severity,
        "Vulnerability": vulnerability,
        "Description": description
    })


def analyze_apk(apk_path):

    findings = []

    apk, _, _ = AnalyzeAPK(apk_path)

    package = apk.get_package()

    file_name = os.path.basename(apk_path)

    ####################################################
    # Debuggable
    ####################################################

    if apk.get_attribute_value("application",
                               "debuggable") == "true":

        add_finding(
            findings,
            file_name,
            package,
            "HIGH",
            "Debuggable Application",
            "Application is debuggable."
        )

    ####################################################
    # Allow Backup
    ####################################################

    backup = apk.get_attribute_value("application",
                                     "allowBackup")

    if backup is None or backup == "true":

        add_finding(
            findings,
            file_name,
            package,
            "MEDIUM",
            "Allow Backup Enabled",
            "android:allowBackup is enabled."
        )

    ####################################################
    # SDK Version
    ####################################################

    target_sdk = apk.get_target_sdk_version()

    try:

        if target_sdk and int(target_sdk) < 30:

            add_finding(
                findings,
                file_name,
                package,
                "MEDIUM",
                "Low Target SDK",
                f"Target SDK = {target_sdk}"
            )

    except:
        pass

    ####################################################
    # Dangerous Permissions
    ####################################################

    permissions = apk.get_permissions()

    for permission in permissions:

        if permission in DANGEROUS_PERMISSIONS:

            add_finding(
                findings,
                file_name,
                package,
                "MEDIUM",
                "Dangerous Permission",
                permission
            )

    ####################################################
    # Exported Activities
    ####################################################

    for activity in apk.get_activities():

        exported = apk.get_attribute_value(
            "activity",
            "exported",
            name=activity
        )

        if exported == "true":

            add_finding(
                findings,
                file_name,
                package,
                "LOW",
                "Exported Activity",
                activity
            )

    ####################################################
    # Exported Services
    ####################################################

    for service in apk.get_services():

        exported = apk.get_attribute_value(
            "service",
            "exported",
            name=service
        )

        if exported == "true":

            add_finding(
                findings,
                file_name,
                package,
                "LOW",
                "Exported Service",
                service
            )

    ####################################################
    # Exported Receivers
    ####################################################

    for receiver in apk.get_receivers():

        exported = apk.get_attribute_value(
            "receiver",
            "exported",
            name=receiver
        )

        if exported == "true":

            add_finding(
                findings,
                file_name,
                package,
                "LOW",
                "Exported Receiver",
                receiver
            )

    return findings


def scan_folder(folder):

    all_findings = []

    for file in os.listdir(folder):

        if file.endswith(".apk"):

            path = os.path.join(folder, file)

            print("Scanning:", file)

            try:

                result = analyze_apk(path)

                all_findings.extend(result)

            except Exception as e:

                print(file, e)

    return all_findings


def save_csv(findings):

    with open("vulnerability_report.csv",
              "w",
              newline="",
              encoding="utf-8") as csvfile:

        writer = csv.DictWriter(csvfile,
                                fieldnames=[
                                    "File",
                                    "Package",
                                    "Severity",
                                    "Vulnerability",
                                    "Description"
                                ])

        writer.writeheader()

        writer.writerows(findings)


if __name__ == "__main__":

    apk_folder = "apk_files"

    findings = scan_folder(apk_folder)

    save_csv(findings)

    print("Finished.")
