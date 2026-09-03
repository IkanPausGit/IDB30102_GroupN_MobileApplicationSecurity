import os
import json
import csv
import hashlib
import argparse
from datetime import datetime

from androguard.core.apk import APK


def calculate_sha256(file_path):
    """
    Calculate SHA-256 hash of the APK file.
    """
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            data = file.read(8192)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


def extract_apk_info(apk_path):
    """
    Extract metadata and security-related features from an APK file.
    """

    apk = APK(apk_path)

    # Basic APK information
    package_name = apk.get_package()
    app_name = apk.get_app_name()

    version_name = apk.get_androidversion_name()
    version_code = apk.get_androidversion_code()

    min_sdk = apk.get_min_sdk_version()
    target_sdk = apk.get_target_sdk_version()

    # Application permissions
    permissions = apk.get_permissions()

    # Android application components
    activities = apk.get_activities()
    services = apk.get_services()
    receivers = apk.get_receivers()
    providers = apk.get_providers()

    # APK file information
    file_size = os.path.getsize(apk_path)
    file_hash = calculate_sha256(apk_path)

    metadata = {
        "apk_file": os.path.basename(apk_path),
        "file_size_bytes": file_size,
        "sha256": file_hash,

        "package_name": package_name,
        "app_name": app_name,

        "version_name": version_name,
        "version_code": version_code,

        "min_sdk_version": min_sdk,
        "target_sdk_version": target_sdk,

        "permissions": permissions,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,

        "number_of_permissions": len(permissions),
        "number_of_activities": len(activities),
        "number_of_services": len(services),
        "number_of_receivers": len(receivers),
        "number_of_providers": len(providers),

        "extracted_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    return metadata


def save_json(data, output_file):
    """
    Save extracted information into JSON format.
    """

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False
        )


def save_csv(data, output_file):
    """
    Save extracted information into CSV format.
    """

    rows = []

    for key, value in data.items():

        # Convert lists into a readable string
        if isinstance(value, list):
            value = "; ".join(value)

        rows.append({
            "feature": key,
            "value": value
        })

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=["feature", "value"]
        )

        writer.writeheader()

        writer.writerows(rows)


def main():

    parser = argparse.ArgumentParser(
        description="APK Metadata and Data Collection Tool"
    )

    parser.add_argument(
        "apk",
        help="Path to the APK file"
    )

    parser.add_argument(
        "--output",
        default="apk_info",
        help="Output file prefix"
    )

    args = parser.parse_args()

    apk_path = args.apk

    # Check whether APK exists
    if not os.path.isfile(apk_path):

        print("[ERROR] APK file was not found.")
        print(f"[INFO] File: {apk_path}")

        return

    # Check extension
    if not apk_path.lower().endswith(".apk"):

        print("[ERROR] The selected file is not an APK.")
        return

    try:

        print("=" * 60)
        print("APK METADATA / DATA COLLECTION TOOL")
        print("=" * 60)

        print(f"\n[+] APK file: {apk_path}")
        print("[+] Extracting APK information...")

        metadata = extract_apk_info(apk_path)

        # Display important information
        print("\n" + "-" * 60)
        print("APK INFORMATION")
        print("-" * 60)

        print(f"App Name       : {metadata['app_name']}")
        print(f"Package Name   : {metadata['package_name']}")
        print(f"Version Name   : {metadata['version_name']}")
        print(f"Version Code   : {metadata['version_code']}")
        print(f"Minimum SDK    : {metadata['min_sdk_version']}")
        print(f"Target SDK     : {metadata['target_sdk_version']}")

        print(f"\nFile Size      : {metadata['file_size_bytes']} bytes")
        print(f"SHA-256        : {metadata['sha256']}")

        print("\nComponent Counts")
        print(f"Permissions    : {metadata['number_of_permissions']}")
        print(f"Activities     : {metadata['number_of_activities']}")
        print(f"Services       : {metadata['number_of_services']}")
        print(f"Receivers      : {metadata['number_of_receivers']}")
        print(f"Providers      : {metadata['number_of_providers']}")

        print("\nPermissions")
        for permission in metadata["permissions"]:
            print(f"  - {permission}")

        # Save JSON
        json_file = args.output + ".json"

        save_json(
            metadata,
            json_file
        )

        # Save CSV
        csv_file = args.output + ".csv"

        save_csv(
            metadata,
            csv_file
        )

        print("\n" + "-" * 60)
        print("DATA COLLECTION COMPLETED")
        print("-" * 60)

        print(f"[+] JSON output : {json_file}")
        print(f"[+] CSV output  : {csv_file}")

    except Exception as error:

        print("\n[ERROR] Failed to analyse APK.")
        print(f"[DETAILS] {error}")


if __name__ == "__main__":
    main()
