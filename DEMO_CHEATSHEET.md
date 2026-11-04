# Sanket (સંકેત • संकेत) — Presentation Day Cheatsheet
> **Keep this sheet open during your presentation with Prof. Ujwala Patigara!**  
> **Major Project 2026–27 | Department of Data Science & Machine Learning, Navrachana University**  
> **Team:** Isha Rajput, Priya Bhatt, Parisha Parmar | **Guide:** Prof. Ujwala Patigara

---

## ⚡ 10-Second Quick Start
To launch the application:
```bash
./backend/venv/bin/python run_app.py
```
*(Automatically starts the FastAPI server and opens `http://localhost:8000` in your browser).*

---

## 🎯 4-Step Live Demonstration Walkthrough

### 1. Tab 1: Multilingual Message Scanner (Text Classifier 1)
- **Language Adaptation:** Click the top-right toggle (**English / हिंदी / ગુજરાતી**) — the entire interface, sample prompts, and safety explanations adapt instantly.
- **1-Click Demo Scenarios:**
  - Click **"⚡ Hindi Electricity Threat"** $\to$ **Verify Message**: Flags **82.9% SCAM** with plain-language Devanagari explanation and urgency tags.
  - Click **"💡 Gujarati PGVCL Bill Scam"** $\to$ Detects fake bill cutoff threat and embedded phishing link.
  - Click **"✅ Safe Transaction Alert"** $\to$ Returns **SAFE (0.1% Risk)** with zero false alarm!
- **Screenshot OCR (Client-side WebAssembly):**
  - Click **"Upload Screenshot (OCR)"** or simply press **`Ctrl+V` / `Cmd+V`** with any WhatsApp screenshot.
  - Shows real-time progress bar ($0 \to 100\%$), extracts the message text, and automatically triggers the scam classifier!

### 2. Tab 2: URL Threat Inspector (URL Classifier 2)
- Click **"🚨 Fake PGVCL APK Link"** (`http://pgvcl-billupdate.top/pay.apk`) $\to$ **Inspect Link**:
  - Flags **HIGH RISK PHISHING (100% Risk)**.
  - Red flags: Untrusted TLD (`.top`), executable Android file download (`.apk`), and lack of SSL (`http://`).
- Click **"🏛️ Official SBI Portal"** (`https://www.onlinesbi.sbi`) $\to$ Correctly verifies legitimate institutional domain.

### 3. Tab 3: QR Code & UPI Quishing Scanner
- Upload or drag any QR code image.
- **OpenCV Engine** decodes raw payload without internet delay.
- **UPI Reverse-Payment Detection:** Distinguishes between standard payment codes and predatory scam codes that pretend to "refund/receive" money while actually triggering a debit from the victim's account!

### 4. Tab 4: Statutory Incident Response & First-Aid (The "Cure" Module)
- When a scam is detected in Tabs 1, 2, or 3, an immediate alert appears:  
  **"🚨 Already clicked, paid money, or entered details? Launch Legal First-Aid (Cure) →"**
- **4 Real-World Compromise Scenarios:**
  1. **Money Debited / UPI Sent:**
     - **MHA Helpline 1930 (Golden Hour Freeze):** Direct call button to trigger CFCFRMS lien on the fraudster's mule account before ATM cashout.
     - **RBI 3-Day Zero Customer Liability Rule:** Citing **RBI Circular DBR.No.Leg.BC.78/09.07.005/2017-18 (Clause 6)** guaranteeing 100% bank reimbursement if reported within 3 working days.
     - **Bank Emergency Directory:** Speed-dial and SMS block numbers for SBI, HDFC, ICICI, Bank of Baroda, PNB, Axis.
  2. **Entered Password / OTP:** Emergency card lockout, clean-device password reset, and session invalidation.
  3. **Installed Malicious APK (PGVCL/AnyDesk):** Immediate Airplane Mode (severing background SMS forwarder), Android Safe Mode boot, and reporting to **DoT Chakshu** (`sancharsaathi.gov.in/sfc`).
  4. **SIM Swap / WhatsApp Hijack:** Telecom carrier lock, **DoT TAFCOP** Aadhaar SIM audit, and WhatsApp 2FA setup.
- **1-Click Official Cyber Police Complaint Draft:** Pre-fills date, amount, transaction ID, and suspect identifier into a formal complaint citing **IT Act 2000 (Sec 66C & 66D)** and **BNS 2023 (Sec 318(4))**.
- **1-Click Family WhatsApp Alert:** Generates localized warning in EN/HI/GU for family WhatsApp groups.

---

## 🔬 Academic Research & Defense Q&A

| Viva Question | Your Bulletproof Answer |
|---|---|
| **What was the Central Research Question?** | *"Does combining message text and structural URL evidence improve scam detection compared to analyzing either source alone across English, Hindi, and Gujarati?"* |
| **Why use Character N-grams for text?** | Indic languages (Hindi, Gujarati) are morphologically rich and agglutinative (prefixes and suffixes attach to root words). Subword Character N-grams (3–5 chars) capture semantic roots and withstand phonetic Hinglish and deliberate typos without OOV tokenization failure. |
| **What were your MuRIL Colab Experimental Findings?** | We fine-tuned `google/muril-base-cased` on Google Colab T4 GPU under 5-fold Stratified Group CV (`PIPELINE_NOTES.md`). Training MuRIL solely on real data achieved 0.948 F1 on English but completely collapsed on regional languages (**0.000 F1 on Real Hindi, 0.000 F1 on Real Gujarati**). Synthetic data augmentation recovered Hindi recall to **100% (8/8 caught, 0.889 F1)** and Gujarati to **57.1% (4/7 caught, 0.533 F1)**, proving that synthetic augmentation is mathematically indispensable for low-resource Indic scam detection. |
| **Why is False Positive Rate (FPR) critical?** | If a safety filter flags legitimate bank alerts or OTPs as scams, users lose trust and disable the protection. Sanket achieves near-zero FPR through legitimate institutional whitelisting and calibrated multi-evidence thresholds. |
| **What is Quishing?** | QR code phishing. Scammers embed deceptive payment or login links inside QR codes (often on WhatsApp or fake electricity bills) to evade email text scanners. Sanket decodes QR codes before URL execution, as recommended by *QsecR (IEEE Access 2023)*. |
| **What is the statutory basis of the Cure module?** | Grounded in: (1) **Ministry of Home Affairs (I4C) Helpline 1930 & CFCFRMS** for real-time account freeze, (2) **RBI Circular DBR.No.Leg.BC.78/09.07.005/2017-18** for 3-day customer zero liability, (3) **IT Act Sec 66C & 66D** and **BNS Sec 318(4)** for formal FIR registration, and (4) **DoT Sanchar Saathi (Chakshu & TAFCOP)** for carrier blacklisting. |

---
**Navrachana University, Vadodara • Major Project 2026-27**

