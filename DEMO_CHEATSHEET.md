# Nirbhay — Presentation Day Quick Demonstration Cheatsheet
> **Keep this tab or printed page open during your presentation with Prof. Ujwala Patigara!**

---

## ⚡ 10-Second Quick Start
To launch the app for the panel:
```bash
python run_app.py
```
*(Or double-click `run_demo.bat` on the Desktop/folder. It opens `http://localhost:8000` automatically).*

---

## 🎯 Live Demonstration Flow (Guaranteed A+ Presentation)

### Step 1: Real-World Consumer App (Live Running of Model - Pointer 1)
1. **Show the Clean Light UI:**
   - Mention: *"Sir/Ma'am, we designed Nirbhay as a real-world, accessible digital safety tool that ordinary citizens in Gujarat and India can easily use to protect themselves from cyber fraud."*
2. **Switch Regional Language:**
   - Use the top language dropdown to switch to **हिन्दी** or **ગુજરાતી**.
   - Show how the whole app adapts into the local language.
3. **1-Tap Demo Scenarios:**
   - Click **"SBI YONO KYC Suspension (Hindi Scam)"** ➔ Click **"Check Message Safety"**.
   - Point out:
     - 🔴 **Threat Level & Risk Score:** 88% Phishing Scam.
     - 💡 **Plain-Language Explanation in Hindi:** Explaining why the message and fake `.xyz` domain are fraudulent.
     - 🔊 **Voice Audio Button:** Click **"Listen Audio Alert"** to play the spoken warning aloud!
     - 👨‍👩‍👧 **"Copy WhatsApp Alert":** Show how a user can copy a pre-formatted fraud warning in 1 click to protect their parents and family groups.
4. **Try a Legitimate Message:**
   - Click **"Legitimate SBI Transaction Alert"** ➔ Click **"Check Message Safety"**.
   - Show how the model accurately identifies verified `.sbi` domains and transactional SMS, returning 🟢 **SAFE (0.6% Risk)** without false alarms!
5. **QR Code Quishing Scanner (Direct link to Paper 2 - QsecR):**
   - Click the **"QR Code Scanner (QsecR)"** tab.
   - Click **"Test UPI QR Code Payment Scam Demo"** ➔ It decodes the hidden payload and evaluates the URL threat!

---

## 🔬 Live Evaluation with Unseen Data (Pointer 2)

When the faculty asks: *"How does the model evaluate on live data?"*

1. Click the top-right button: **`Faculty Demo (Pointer 2)`**.
2. A slide-out console appears showing:
   - **Ablation Study Matrix:**
     - Text-Only Model vs. URL-Only Model vs. Multi-Evidence Fusion.
     - Proving that **Multi-Evidence Fusion** achieves the highest F1-Score and lowest False Positive Rate (FPR).
   - **Per-Language FPR:** English (0.0%), Hindi (0.0%), Gujarati (0.0%), directly addressing the gap in *Staples et al. (IEEE PST 2023)*.
3. **Run Live Test:**
   - Click **"Load 10 Samples"**.
   - Click **"Run Live Test"**.
   - Show the live evaluation table updating on the spot with real-time Precision, Recall, and PASS/FAIL marks!

---

## 💬 Answers to Expected Viva / Defense Questions

| Question | Your Answer |
|---|---|
| **Why not just use keyword matching?** | Keyword matching fails on new vocabulary shifts and cannot analyze domain structures (IP hosts, entropy, brand-spoofing subdomains). Nirbhay combines subword character n-grams with 25+ lexical URL structural features. |
| **Why did you use Character N-grams for text?** | Indic languages (Hindi, Gujarati) are highly agglutinative, meaning prefixes and suffixes attach to root words. Character n-grams (3–5 grams) capture morphological roots across Devanagari and Gujarati scripts even with typos or slight dialect variations. |
| **What is Quishing?** | QR code phishing. Attackers embed deceptive payment or login links inside QR codes (often on WhatsApp or fake electricity bills) to evade email text scanners. Nirbhay decodes QR codes before URL execution, as recommended by *QsecR (IEEE Access 2023)*. |
| **Why is False Positive Rate (FPR) critical?** | If a safety app flags legitimate bank alerts or OTPs as scams, users lose trust and ignore real warnings. Nirbhay explicitly minimizes FPR to near zero using legitimate domain whitelisting and fusion calibration. |

---
**Team Members:** Isha Rajput, Parisha Parmar, Priya Bhatt  
**Navrachana University, Vadodara • DS-ML Major Project 2026-27**

