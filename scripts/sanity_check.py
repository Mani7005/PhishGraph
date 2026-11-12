"""Real-world sanity check: does the model raise false alarms on everyday sites?

The test-set metrics measure performance on the dataset's distribution. This
script checks hand-picked URLs that look like normal browsing (small
businesses, universities, regional sites, real login pages) and typical
phishing patterns. Allowlisted sites are skipped so the MODEL is tested.

    python scripts/sanity_check.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from phishgraph.predictor import Predictor  # noqa: E402

BENIGN = [
    "https://shop.localbakery.in/", "https://mail.myuniversity.edu/owa/", "https://www.iitb.ac.in/",
    "https://example-dentist.com/", "https://some-small-blog.net/2021/05/recipes",
    "https://portal.kseb.in/login", "https://accounts.zoho.in/signin", "https://my.vodafone.co.uk/account",
    "https://www.cafecoffeeday.com/", "https://blog.jetbrains.com/idea/", "https://www.lakmeindia.com/",
    "https://login.uni-heidelberg.de/", "https://www.municipalcorporation.gov.in/services",
    "https://app.hubspot.com/login", "https://secure.bankofmaharashtra.in/", "https://www.myntra.com/login",
    "https://student.portal.vit.ac.in/", "https://www.greenleafnursery.co.uk/checkout",
    "https://my.ourcityclinic.org/patient/login", "https://www.thehindu.com/news/national/",
    "https://careers.infosys.com/login", "https://www.hdfcbank.com/personal/login",
    "https://login.salesforce.com/", "https://app.asana.com/-/login", "https://www.zomato.com/ncr",
    "https://id.atlassian.com/login", "https://www.decathlon.in/cart", "https://web.whatsapp.com/",
    "https://www.bigbasket.com/auth/login/", "https://moodle.college.edu/login/index.php",
]
PHISHING = [
    "http://paypal.com-secure-login.verify-account.xyz/webscr/signin.php",
    "http://secure-netflix-billing-update.top/account", "https://microsoft-office365-verify.web.app/login",
    "http://192.168.4.20/bankofamerica/login.php", "https://amaz0n-orders-support.com/",
    "http://sbi-kyc-update.online/login.php", "https://apple-id-locked.support-verify.cn/",
    "http://hdfc-netbanking-verify.xyz/index.php", "https://wellsfargo.secure-auth-login.ru/",
    "https://dhl-parcel-redelivery.info/track?id=88231", "http://login-microsoftonline.verify-user.tk/",
    "https://instagram-copyright-appeal.web.app/", "http://update-billing-netflix.com.account-verify.icu/",
]


def main():
    P = Predictor()
    rows = []
    for label, urls in (("benign", BENIGN), ("phishing", PHISHING)):
        for u in urls:
            r = P.predict(u)
            if r["verdict"] == "trusted":
                continue
            rows.append((label, r["verdict"], r["probability"], u))
    for label, verdict, p, u in rows:
        flag = "OK " if (label == "benign") == (verdict == "safe") else "XX "
        print(f"{flag}{label:9s} {verdict:10s} {p:.3f}  {u}")
    b = [r for r in rows if r[0] == "benign"]
    ph = [r for r in rows if r[0] == "phishing"]
    print(f"\nbenign scored: {len(b)} | red-banner false alarms: {sum(r[1] == 'phishing' for r in b)} "
          f"| amber 'suspicious': {sum(r[1] == 'suspicious' for r in b)}")
    print(f"phishing scored: {len(ph)} | caught (phishing or suspicious): {sum(r[1] != 'safe' for r in ph)}")


if __name__ == "__main__":
    main()
