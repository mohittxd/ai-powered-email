"""
batch_rank.py — Batch Email Risk Ranking

Accepts a list of emails and outputs them ranked by descending risk_score.

Usage:
  python batch_rank.py --input emails.json --output rankings.csv
  python batch_rank.py --demo
"""

import argparse
import csv
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
from predict import predict_email


def rank_emails(emails):
    """
    Rank a list of emails by risk score.

    Args:
        emails: list of dicts with keys: subject, body, sender (opt), receiver (opt), urls (opt)

    Returns:
        list of dicts sorted by descending risk_score
    """
    results = []
    for i, email in enumerate(emails):
        result = predict_email(
            subject=email.get("subject", ""),
            body=email.get("body", ""),
            sender=email.get("sender"),
            receiver=email.get("receiver"),
            urls=email.get("urls"),
        )
        result["email_id"] = email.get("id", i)
        results.append(result)

    results.sort(key=lambda x: -x["risk_score"])

    for rank, r in enumerate(results, 1):
        r["rank"] = rank

    return results


def main():
    parser = argparse.ArgumentParser(description="Batch email risk ranking")
    parser.add_argument("--input", help="JSON file with list of email objects")
    parser.add_argument("--output", help="Output CSV file path")
    parser.add_argument("--demo", action="store_true", help="Run demo with sample emails")
    args = parser.parse_args()

    if args.demo:
        emails = [
            {
                "id": "demo_001",
                "subject": "URGENT: Your account has been compromised!",
                "body": "Dear user, we have detected unauthorized access to your account. "
                        "Please click the link below immediately to verify your identity: "
                        "http://phishing-site.com/verify Your account will be suspended in 24 hours.",
                "sender": "security@totaly-not-phishing.com",
                "receiver": "victim@gmail.com",
                "urls": 1,
            },
            {
                "id": "demo_002",
                "subject": "Meeting notes from Tuesday",
                "body": "Hi team, here are the notes from our meeting yesterday. "
                        "We discussed the Q3 roadmap and agreed on the following priorities. "
                        "Please review and let me know if anything is missing.",
                "sender": "colleague@company.com",
                "receiver": "user@company.com",
                "urls": 0,
            },
            {
                "id": "demo_003",
                "subject": "Congratulations! You've won $1,000,000!!!",
                "body": "YOU HAVE BEEN SELECTED AS OUR WINNER!!! "
                        "Send your bank details to claim your prize NOW!!! "
                        "http://totally-real-prize.com/claim http://another-scam.net/verify",
                "sender": "prince@random-country.ng",
                "receiver": "lucky-person@yahoo.com",
                "urls": 2,
            },
            {
                "id": "demo_004",
                "subject": "RE: Build pipeline failure on main branch",
                "body": "The CI/CD pipeline is failing on the main branch. "
                        "Error logs show a test failure in test_auth.py:42. "
                        "Can someone look into this? Here's the log output: "
                        "https://ci.example.com/build/12345",
                "sender": "ci-notifications@our-org.com",
                "receiver": "dev-team@our-org.com",
                "urls": 1,
            },
            {
                "id": "demo_005",
                "subject": "Make $$$ working from home!!!",
                "body": "EARN $5000/DAY with this ONE WEIRD TRICK!!! "
                        "Banks HATE us! Click here to start making money NOW! "
                        "Limited time offer! ACT NOW!!! "
                        "http://make-money-fast.biz/secret http://work-from-home-scam.io/apply",
                "sender": "money-maker@freemail.selfip.org",
                "receiver": "target@hotmail.com",
                "urls": 2,
            },
        ]
    elif args.input:
        with open(args.input) as f:
            emails = json.load(f)
    else:
        print("Error: provide --input or --demo", file=sys.stderr)
        sys.exit(1)

    print(f"Ranking {len(emails)} emails...")
    results = rank_emails(emails)

    # Print table
    print(f"\n{'Rank':>6} {'ID':>12} {'Score':>8} {'Class':>6} {'Confidence':>10} Subject")
    print("-" * 90)
    for r in results:
        subject_preview = r.get("email_id", "")[:30]
        # Find original email subject
        for e in emails:
            if e.get("id") == r.get("email_id"):
                subject_preview = e.get("subject", "")[:40]
                break
        print(f"{r['rank']:>6} {str(r.get('email_id', '')):>12} "
              f"{r['risk_score']:>8.4f} {r['predicted_class']:>6} "
              f"{r['confidence']:>10} {subject_preview}")

    # Save output
    if args.output:
        df = pd.DataFrame(results)
        df.to_csv(args.output, index=False)
        print(f"\nSaved to {args.output}")
    else:
        print(f"\nFull results:")
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
