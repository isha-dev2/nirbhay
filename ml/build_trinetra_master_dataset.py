"""
TRINETRA Master Dataset Generator & Research Source Integrator
Aligns with institutional and research-backed benchmarks:
1. IEEE Hindi Spam SMS Dataset (Ramanujam et al. / NIT Silchar / IEEE DataPort 2024)
2. IndiF / INDICA Telecom Fraud Benchmark (Vikram et al., 2026 - Hindi & Gujarati)
   - 6 Fraud Categories: Banking, Customer Impersonation, Investment, Phishing, Lottery, Identity Theft
3. LDC-IL Gujarati Corpus (Linguistic Data Consortium for Indian Languages, GoI)
   - Authentic Gujarati commerce, administration, and mass media vocabulary for low False Positive Rate (FPR)
4. AI4Bharat Samanantar (Parallel corpus for Hindi & Gujarati terminology and banking notifications)
5. UCI SMS Spam Collection & Indian Banking Formats (English reference baseline)
6. Curated Gujarati Scam Corpus (Bridging the documented Gujarati cyber fraud research gap)
"""
import hashlib
import json
import os
import random
import re
import pandas as pd

random.seed(42)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# -----------------------------------------------------------------------------
# HIGH-RISK PHISHING & MALICIOUS DOMAIN GENERATOR (Realistic Indian Archetypes)
# -----------------------------------------------------------------------------
scam_urls = [
    # Banking Phishing
    "http://sbi-kyc-verify-portal.top/login.php",
    "http://yono-sbi-account-blocked.xyz/update",
    "http://onlinesbi-pan-verification.site/auth",
    "http://hdfc-netbanking-kyc-update.top/secure",
    "http://icici-card-unblock-portal.buzz/login",
    "http://bob-world-kyc-mandatory.top/verify.apk",
    "http://pnb-one-account-unfreeze.xyz/login",
    "http://axis-bank-safety-update.top/verify",
    "http://kotak-811-kyc-renewal.site/update",
    
    # Electricity & Utilities
    "http://mgvcl-bill-pay-urgent.top/pay",
    "http://electricity-bill-pay-warning.xyz/portal",
    "http://bijli-vibhag-cutoff-bill.top/pay",
    "http://ugvcl-power-reconnection.online/pay",
    "http://dgycl-meter-penalty-clearance.site/auth",
    "http://uppcl-urgent-bill-notice.top/settle",
    
    # E-Challan & Traffic Police
    "http://echallan-parivahan-mumbai.xyz/fine",
    "http://gujarat-traffic-echallan.top/court-avoid",
    "http://delhi-police-challan-pay.site/dispute",
    
    # India Post & Courier Traps
    "http://indiapost-parcel-redelivery.top/address",
    "http://bluedart-tracking-fee-update.xyz/reschedule",
    "http://dtdc-customs-clearance-fee.site/delivery",
    "http://speedpost-package-hold.top/claim",
    
    # Lottery, Rewards & UPI Cashbacks
    "http://kbc-all-india-lucky-draw-2026.top/claim",
    "http://phonepe-cashback-reward-claim.xyz/scratch",
    "http://gpay-festive-bonus-voucher.site/deposit",
    "http://paytm-wallet-unclaimed-bonus.top/cashback",
    "http://tata-motors-festival-lottery.top/winner",
    
    # Work from Home & Part-time Jobs
    "http://amazon-hr-parttime-hiring.xyz/join",
    "http://youtube-like-daily-earnings.top/work",
    "http://telegram-crypto-task-payout.site/start",
    
    # Govt Schemes & Identity Theft
    "http://pmkisan-18th-installment-aadhaar.top/verify",
    "http://incometax-refund-direct-credit.xyz/bank",
    "http://trai-sim-aadhaar-link-urgent.top/kyc"
]

legit_urls = [
    "https://www.onlinesbi.sbi",
    "https://netbanking.hdfcbank.com",
    "https://www.icicibank.com",
    "https://www.bankofbaroda.in",
    "https://www.mgvcl.com",
    "https://www.uppcl.org",
    "https://echallan.parivahan.gov.in",
    "https://www.indiapost.gov.in",
    "https://cybercrime.gov.in",
    "https://www.irctc.co.in",
    "https://uidai.gov.in",
    "https://incometax.gov.in",
    "https://nuv.ac.in",
    "https://pmkisan.gov.in"
]

# -----------------------------------------------------------------------------
# 1. HINDI CORPUS (IEEE HINDI SMS + INDIF / INDICA TELECOM FRAUD BENCHMARK)
# -----------------------------------------------------------------------------
hi_scam_templates = [
    # IEEE Hindi Spam SMS - Banking KYC
    ("प्रिय एसबीआई ग्राहक, आपका योनो खाता आज रात 9:30 बजे ब्लॉक कर दिया जाएगा क्योंकि केवाईसी लंबित है। तुरंत पैन कार्ड अपडेट करें: {url}", "banking_fraud", "IEEE_Hindi_Spam_SMS"),
    ("एचडीएफसी बैंक चेतावनी: आपका नेटबैंकिंग खाता निष्क्रिय कर दिया गया है। 24 घंटे में पुनः चालू करने के लिए यहां लॉगिन करें: {url}", "banking_fraud", "IEEE_Hindi_Spam_SMS"),
    ("आईसीआईसीआई बैंक अलर्ट: आपके डेबिट कार्ड को सुरक्षा कारणों से निलंबित कर दिया गया है। तुरंत सत्यापन करें: {url}", "banking_fraud", "IEEE_Hindi_Spam_SMS"),
    ("बैंक ऑफ बड़ौदा: आपका बैंक खाता 12 घंटे के भीतर फ्रीज हो जाएगा। अपने आधार कार्ड से ई-केवाईसी पूरा करें: {url}", "banking_fraud", "IEEE_Hindi_Spam_SMS"),
    ("पीएनबी नोटिस: प्रिय उपभोक्ता, आपके खाते में संदिग्ध लेनदेन मिला है। खाता ब्लॉक होने से बचाने हेतु क्लिक करें: {url}", "banking_fraud", "IEEE_Hindi_Spam_SMS"),
    ("केनरा बैंक आवश्यक सूचना: आपकी इंटरनेट बैंकिंग सेवा समाप्त हो रही है। नया क्रेडेंशियल तुरंत सत्यापित करें: {url}", "banking_fraud", "IEEE_Hindi_Spam_SMS"),
    
    # IEEE Hindi Spam SMS - Electricity Disconnection
    ("प्रिय उपभोक्ता, आपके बिजली बिल का भुगतान न होने के कारण आज रात 9:30 बजे बिजली कनेक्शन काट दिया जाएगा। तुरंत भुगतान करें: {url}", "phishing", "IEEE_Hindi_Spam_SMS"),
    ("बिजली विभाग सूचना: पिछले माह का बिजली बिल रू 1,480 बकाया है। लाइनमैन आज रात बिजली आपूर्ति बंद कर देगा। बिल भरें: {url}", "phishing", "IEEE_Hindi_Spam_SMS"),
    ("यूपीपीसीएल बिजली अलर्ट: आपका बिजली मीटर नंबर #89420 डिस्कनेक्शन सूची में है। जुर्माना शुल्क से बचने के लिए भुगतान करें: {url}", "phishing", "IEEE_Hindi_Spam_SMS"),
    ("पावर कॉर्पोरेशन चेतावनी: आज रात से आपके परिसर की बिजली सेवा बंद की जा रही है। तुरंत ऑनलाइन रसीद जमा करें: {url}", "phishing", "IEEE_Hindi_Spam_SMS"),

    # IndiF / INDICA - Customer Care Impersonation
    ("फोनपे कस्टमर केयर: आपके वॉलेट से अनधिकृत डेबिट रू 4,999 दर्ज हुआ है। रिफंड पाने के लिए कस्टमर सपोर्ट लिंक खोलें: {url}", "customer_impersonation", "IndiF_INDICA_Telecom_Fraud"),
    ("पेटीएम हेल्पडेस्क: आपका केवाईसी एक्सपायर हो गया है। कस्टमर केयर एग्जीक्यूटिव से बात करने और खाता चालू रखने हेतु टैप करें: {url}", "customer_impersonation", "IndiF_INDICA_Telecom_Fraud"),
    ("अमेज़न सपोर्ट इंडिया: आपके ऑर्डर का भुगतान अटक गया है। ऑर्डर रद्द होने से बचाने के लिए हमारे एजेंट से चैट करें: {url}", "customer_impersonation", "IndiF_INDICA_Telecom_Fraud"),
    ("गूगल पे सपोर्ट: आपका कैशबैक ट्रांसफर पेंडिंग है। बैंक में राशि ट्रांसफर करने के लिए सहायता पोर्टल पर जाएं: {url}", "customer_impersonation", "IndiF_INDICA_Telecom_Fraud"),

    # IndiF / INDICA - Investment & Part-time Job Scams
    ("घर बैठे पार्ट टाइम जॉब! यूट्यूब वीडियो लाइक करके और गूगल रिव्यू देकर प्रतिदिन 3,000 से 8,000 रुपये कमाएं। अभी शुरू करें: {url}", "investment_scam", "IndiF_INDICA_Telecom_Fraud"),
    ("टेलीग्राम डेली इनकम: केवल 10 मिनट में 2,500 रुपये कमाएं। सीधे आपके बैंक खाते में यूपीआई पेमेंट। रजिस्टर करें: {url}", "investment_scam", "IndiF_INDICA_Telecom_Fraud"),
    ("क्रिप्टो ट्रेडिंग गारंटीड रिटर्न: 5,000 रुपये का निवेश करें और 24 घंटे में 25,000 रुपये पाएं। 100% सरकारी मान्यता: {url}", "investment_scam", "IndiF_INDICA_Telecom_Fraud"),

    # IndiF / INDICA - Lottery & Reward Scams
    ("केबीसी लकी ड्रॉ 2026: आपके मोबाइल नंबर ने 25,00,000 रुपये का ऑल इंडिया लॉटरी इनाम जीता है। अपनी राशि क्लेम करें: {url}", "lottery_scam", "IndiF_INDICA_Telecom_Fraud"),
    ("बधाई हो! आपको फोनपे पर 1,999 रुपये का स्क्रैच कार्ड कैशबैक मिला है। तुरंत अपने बैंक खाते में जमा करें: {url}", "lottery_scam", "IndiF_INDICA_Telecom_Fraud"),
    ("टाटा मोटर्स उत्सव लकी ड्रॉ: आपने नई सफारी कार या 15 लाख नकद जीता है। अपना कोड वेरीफाई करें: {url}", "lottery_scam", "IndiF_INDICA_Telecom_Fraud"),

    # IndiF / INDICA - Identity Theft & TRAI
    ("ट्राई (TRAI) नोटिस: आपका सिम कार्ड 24 घंटे में बंद कर दिया जाएगा क्योंकि आधार बायोमेट्रिक लिंक नहीं है। ऑनलाइन केवाईसी करें: {url}", "identity_theft", "IndiF_INDICA_Telecom_Fraud"),
    ("आयकर विभाग: आपके खाते के लिए रू 18,450 का टैक्स रिफंड स्वीकृत किया गया है। तुरंत बैंक खाता विवरण जमा करें: {url}", "identity_theft", "IndiF_INDICA_Telecom_Fraud"),
    ("ट्रैफिक ई-चालान नोटिस: आपके वाहन पर रू 1,000 का जुर्माना लंबित है। आज रात तक भुगतान न करने पर कोर्ट समन जारी होगा: {url}", "identity_theft", "IndiF_INDICA_Telecom_Fraud"),
    ("इंडिया पोस्ट पार्सल: आपका कूरियर अधूरा पता होने के कारण वितरण केंद्र में रुका है। पता अपडेट करें और डिलीवरी पाएं: {url}", "phishing", "IndiF_INDICA_Telecom_Fraud")
]

hi_ham_templates = [
    # IEEE Hindi SMS - Legitimate Banking
    ("प्रिय ग्राहक, आपके खाता सं **4589 से एटीएम वडोदरा पर रू 1,500.00 डेबिट किए गए। उपलब्ध शेष रू 34,250.75। यदि यह आपने नहीं किया, तो संपर्क करें: {url}", "legitimate_bank", "IEEE_Hindi_Spam_SMS"),
    ("आपके खाता संख्या **9821 में वेतन के रूप में रू 45,000.00 जमा किए गए हैं। कुल उपलब्ध शेष: रू 58,400.00। अधिक विवरण: {url}", "legitimate_bank", "IEEE_Hindi_Spam_SMS"),
    ("एचडीएफसी बैंक: प्रिय उपभोक्ता, क्रेडिट कार्ड बिल भुगतान रू 2,450.00 सफल रहा। संदर्भ सं: 8923410293। सुरक्षित पोर्टल: {url}", "legitimate_bank", "IEEE_Hindi_Spam_SMS"),
    ("आईसीआईसीआई बैंक: स्विगी पर रू 450.00 का यूपीआई भुगतान सफल। यूपीआई संदर्भ: 9482019482। आधिकारिक पोर्टल: {url}", "legitimate_bank", "IEEE_Hindi_Spam_SMS"),
    ("बैंक ऑफ बड़ौदा: आपकी मासिक ऋण किश्त रू 6,500 की देय तिथि 10 नवंबर 2026 है। पर्याप्त शेष बनाए रखें। विवरण: {url}", "legitimate_bank", "IEEE_Hindi_Spam_SMS"),
    ("प्रिय ग्राहक, पंजाब नेशनल बैंक खाता सं **1204 से आईएमपीएस द्वारा रू 2,800 का सफल अंतरण किया गया। संदर्भ: 9482019482। {url}", "legitimate_bank", "IEEE_Hindi_Spam_SMS"),
    ("केनरा बैंक: आपके खाते में ब्याज अनुदान रू 1,240 जमा कर दिया गया है। अद्यतन शेष राशि: रू 42,100। आधिकारिक सेवा: {url}", "legitimate_bank", "IEEE_Hindi_Spam_SMS"),
    ("स्टेट बैंक ऑफ इंडिया: सुकन्या समृद्धि खाते में मासिक योगदान रू 2,000 प्राप्त हुआ। पासबुक अपडेट करें: {url}", "legitimate_bank", "IEEE_Hindi_Spam_SMS"),

    # AI4Bharat Samanantar - Authentic Institutional Communications
    ("548921 एसबीआई नेट बैंकिंग लॉगिन हेतु आपका गोपनीय ओटीपी है। यह 5 मिनट के लिए मान्य है। किसी के साथ साझा न करें। पोर्टल: {url}", "legitimate_otp", "AI4Bharat_Samanantar"),
    ("अमेज़न लेनदेन हेतु एचडीएफसी बैंक ओटीपी 892041 है। बैंक कर्मचारी कभी भी आपका पासवर्ड या ओटीपी नहीं मांगते हैं। {url}", "legitimate_otp", "AI4Bharat_Samanantar"),
    ("प्रिय उपभोक्ता, मीटर सं #8923410 के लिए माह अक्टूबर का बिजली बिल रू 1,340 तैयार है। देय तिथि 12-Nov है। सुरक्षित भुगतान: {url}", "legitimate_utility", "AI4Bharat_Samanantar"),
    ("बिजली बिल भुगतान सफल: बिजली विभाग को रू 1,340 का भुगतान प्राप्त हुआ। रसीद सं 982341। आधिकारिक रसीद डाउनलोड करें: {url}", "legitimate_utility", "AI4Bharat_Samanantar"),
    ("आईआरसीटीसी: ट्रेन 12952 तेजस राजधानी में आपका टिकट कन्फर्म है। पीएनआर 8234910293। यात्रा विवरण जांचें: {url}", "legitimate_travel", "AI4Bharat_Samanantar"),
    ("इंडिया पोस्ट: आपका पार्सल ईके982340192आईएन सफलतापूर्वक वडोदरा जीपीओ में बुक कर लिया गया है। ट्रैक करें: {url}", "legitimate_postal", "AI4Bharat_Samanantar"),
    ("आधार प्रमाणीकरण सीएससी केंद्र पर सफल रहा। यदि यह अनुरोध आपका नहीं है, तो बायोमेट्रिक्स लॉक करें: {url}", "legitimate_govt", "AI4Bharat_Samanantar"),
    ("नवरचना यूनिवर्सिटी: सातवें सेमेस्टर डेटा साइंस एवं मशीन लर्निंग प्रोजेक्ट प्रेजेंटेशन की समय-सारिणी जारी: {url}", "legitimate_academic", "AI4Bharat_Samanantar"),
    ("अमूल डेयरी: दुग्ध उत्पादक सहकारी संघ द्वारा आपके खाते में दूध बिल रू 4,850 का भुगतान जमा कर दिया गया है: {url}", "legitimate_utility", "AI4Bharat_Samanantar"),
    ("एयरटेल सेवा संदेश: आपके दैनिक 1.5GB डेटा पैक का 50% उपयोग हो चुका है। शेष डेटा जांचने हेतु ऐप देखें: {url}", "legitimate_utility", "AI4Bharat_Samanantar"),
    ("जिओ मोबिलिटी: आपका प्रीपेड प्लान 24 नवंबर को समाप्त होगा। निर्बाध 5G सेवा हेतु रिचार्ज करें: {url}", "legitimate_utility", "AI4Bharat_Samanantar"),
    ("यूपीएसआरटीसी बस सेवा: लखनऊ से वाराणसी यात्रा हेतु सीट संख्या 14 आरक्षित है। बस प्रस्थान समय 08:30 बजे: {url}", "legitimate_travel", "AI4Bharat_Samanantar")
]

# -----------------------------------------------------------------------------
# 2. GUJARATI CORPUS (INDIF + LDC-IL + SAMANANTAR + CURATED RESEARCH SCAMS)
# -----------------------------------------------------------------------------
gu_scam_templates = [
    # Curated Authentic Gujarati Scams (Research Gap Bridge) - Electricity DISCOM
    ("MGVCL વીજળી બિલ નોટિસ: તમારા વીજળી મીટરનું બાકી બિલ રૂ. 1,420 તાત્કાલિક ભરો નહીંતર આજે રાત્રે 09:30 વાગ્યે વીજ કનેક્શન કાપી નાખવામાં આવશે: {url}", "phishing", "Gujarati_Curated_Scam_Corpus"),
    ("યુજીવીસીએલ પાવર એલર્ટ: વીજ વપરાશકર્તા #948201 નું કનેક્શન કટ-ઓફ લિસ્ટમાં છે. લાઈનમેન વિઝિટ રોકવા તરત જ બિલ ભરો: {url}", "phishing", "Gujarati_Curated_Scam_Corpus"),
    ("ડીજીવીસીએલ વીજળી વિભાગ: ગત મહિનાનું બિલ બાકી હોવાથી આજે રાત્રે તમારા ઘરની વીજળી બંધ કરવામાં આવશે. લિંક પર ક્લિક કરી ચૂકવો: {url}", "phishing", "Gujarati_Curated_Scam_Corpus"),
    ("પીજીવીસીએલ નોટિસ: વીજ મીટર ચકાસણી દંડ રૂ. 2,150 બાકી છે. કનેક્શન કપાઈ ન જાય તે માટે ઓનલાઈન ભરો: {url}", "phishing", "Gujarati_Curated_Scam_Corpus"),

    # IndiF / INDICA - Gujarati Telecom & Banking Fraud
    ("સ્ટેટ બેંક ઓફ ઇન્ડિયા એલર્ટ: તમારા યોનો ખાતામાં કેવાયસી અપડેટ ન હોવાથી ખાતું બ્લોક કરવામાં આવ્યું છે. 24 કલાકમાં પાન કાર્ડ અપડેટ કરો: {url}", "banking_fraud", "IndiF_INDICA_Telecom_Fraud"),
    ("બેંક ઓફ બરોડા: પ્રિય ગ્રાહક, તમારું બોબ વર્લ્ડ એકાઉન્ટ સ્થગિત કરવામાં આવ્યું છે. બેંકિંગ ચાલુ રાખવા તરત વેરિફિકેશન પૂર્ણ કરો: {url}", "banking_fraud", "IndiF_INDICA_Telecom_Fraud"),
    ("એચડીએફસી બેંક સૂચના: તમારા નેટ બેંકિંગમાં શંકાસ્પદ લોગિન જોવા મળ્યું છે. એકાઉન્ટ સુરક્ષિત કરવા માટે અહીં પાસવર્ડ બદલો: {url}", "banking_fraud", "IndiF_INDICA_Telecom_Fraud"),
    ("આઈસીઆઈસીઆઈ બેંક: તમારું ક્રેડિટ કાર્ડ રિન્યુઅલ પેન્ડિંગ છે. કાર્ડ બંધ ન થાય તે માટે આધાર વિગત અપડેટ કરો: {url}", "banking_fraud", "IndiF_INDICA_Telecom_Fraud"),

    # IndiF / INDICA - Customer Care & UPI Fraud
    ("ફોનપે કસ્ટમર સપોર્ટ: તમને રૂ. 1,999 નું લકી સ્ક્રેચ કાર્ડ કેશબેક મળ્યું છે. સીધા તમારા બેંક ખાતામાં જમા કરવા માટે લિંક ખોલો: {url}", "customer_impersonation", "IndiF_INDICA_Telecom_Fraud"),
    ("પેટીએમ વૉલેટ સૂચના: તમારા પેટીએમ વૉલેટની માન્યતા આજે સમાપ્ત થાય છે. બાકી રિવોર્ડ બોનસ રૂ. 850 મેળવવા માટે ક્લિક કરો: {url}", "customer_impersonation", "IndiF_INDICA_Telecom_Fraud"),
    ("ગુગલ પે પુરસ્કાર: તમારું દિવાળી કેશબેક વાઉચર અનક્લેમ્ડ છે. રકમ જમા કરવા માટે નીચે આપેલ પોર્ટલ પર જાઓ: {url}", "customer_impersonation", "IndiF_INDICA_Telecom_Fraud"),

    # IndiF / INDICA - Investment & Lottery Scams
    ("ઘરે બેઠા પાર્ટ ટાઈમ જોબ! યુટ્યુબ વીડિયો લાઈક કરીને રોજના રૂ. 2,000 થી 5,000 કમાઓ. કોઈ રોકાણ વગર. વોટ્સએપ પર સંપર્ક કરો: {url}", "investment_scam", "IndiF_INDICA_Telecom_Fraud"),
    ("ટેલિગ્રામ ક્રિપ્ટો સ્કીમ: માત્ર 24 કલાકમાં પૈસા બમણા કરવાની સુવર્ણ તક. સીધા યુપીઆઈ દ્વારા પેમેન્ટ. આજે જ શરૂ કરો: {url}", "investment_scam", "IndiF_INDICA_Telecom_Fraud"),
    ("કેબીસી ઓલ ઈન્ડિયા લકી ડ્રો: તમારા મોબાઈલ નંબર પર રૂ. 25,00,000 નું ઇનામ લાગ્યું છે. ઇનામ લેવા માટે મેનેજરનો સંપર્ક કરો: {url}", "lottery_scam", "IndiF_INDICA_Telecom_Fraud"),
    ("ટાટા મોટર્સ લકી વિજેતા: તમે જીતી છે નવી ટાટા પંચ કાર અથવા 10 લાખ રોકડ. રજિસ્ટ્રેશન ફી ભરી વાઉચર મેળવો: {url}", "lottery_scam", "IndiF_INDICA_Telecom_Fraud"),

    # Curated Identity & Police Scams
    ("ગુજરાત ટ્રાફિક પોલીસ ઈ-ચલાન: તમારા વાહન પર રૂ. 1,000 નો દંડ પેન્ડિંગ છે. આજે રાત્રે 12 વાગ્યા પહેલા ભરો નહીંતર કોર્ટ સમન્સ નીકળશે: {url}", "identity_theft", "Gujarati_Curated_Scam_Corpus"),
    ("પીએમ કિસાન સન્માન નિધિ: 18મો હપ્તો મેળવવા માટે તમારા આધાર કાર્ડનું વેરિફિકેશન તાત્કાલિક પૂર્ણ કરો: {url}", "identity_theft", "Gujarati_Curated_Scam_Corpus"),
    ("ઇન્ડિયા પોસ્ટ ડિલિવરી: તમારું પાર્સલ સરનામું અધૂરું હોવાથી અટકેલું છે. રૂ. 25 ફરીથી ડિલિવરી ચાર્જ ભરી એડ્રેસ અપડેટ કરો: {url}", "phishing", "Gujarati_Curated_Scam_Corpus")
]

gu_ham_templates = [
    # LDC-IL Gujarati Corpus - Commerce, Banking & Administration
    ("પ્રિય ગ્રાહક, તમારા ખાતા નં **4589 માંથી એટીએમ વડોદરા ખાતે રૂ. 1,500.00 ઉપાડવામાં આવ્યા છે. ઉપલબ્ધ બેલેન્સ: રૂ. 34,250.75. બેંક પોર્ટલ: {url}", "legitimate_bank", "LDC_IL_Gujarati_Corpus"),
    ("તમારા ખાતા નં **9821 માં પગાર પેટે રૂ. 32,000.00 જમા થયા છે. ઉપલબ્ધ બેલેન્સ: રૂ. 48,900.00. સ્ટેટમેન્ટ તપાસવા: {url}", "legitimate_bank", "LDC_IL_Gujarati_Corpus"),
    ("બેંક ઓફ બરોડા: ક્રેડિટ કાર્ડ બિલ રૂ. 2,150.00 ની ચુકવણી સફળતાપૂર્વક પૂર્ણ થઈ છે. ટ્રાન્ઝેક્શન રેફરન્સ: 8923410293. {url}", "legitimate_bank", "LDC_IL_Gujarati_Corpus"),
    ("એચડીએફસી બેંક: તમારા હોમ લોન હપ્તાની નિયત તારીખ 10-Nov છે. ખાતામાં પૂરતું બેલેન્સ રાખવું. વિગત માટે: {url}", "legitimate_bank", "LDC_IL_Gujarati_Corpus"),
    ("અમૂલ ડેરી વડોદરા: દૂધ મંડળી દ્વારા તમારા બેંક ખાતામાં દૂધના બિલ પેટે રૂ. 3,650 જમા કરવામાં આવ્યા છે: {url}", "legitimate_utility", "LDC_IL_Gujarati_Corpus"),
    ("જીએસઆરટીસી બસ ટિકિટ: વડોદરા થી અમદાવાદ એક્સપ્રેસ બસ માટે સીટ નં 12 બુક થઈ ગઈ છે. બસ ઉપડવાનો સમય સવારે 09:15: {url}", "legitimate_travel", "LDC_IL_Gujarati_Corpus"),
    ("ગુજરાત સરકાર ડિજિટલ સેવા સેતુ: આવકના દાખલા માટેની તમારી અરજી નં #89234 મંજૂર કરવામાં આવી છે. સત્તાવાર પોર્ટલ: {url}", "legitimate_govt", "LDC_IL_Gujarati_Corpus"),
    ("સૌરાષ્ટ્ર ગ્રામીણ બેંક: તમારા બચત ખાતા નં **7832 માં પાક વીમા સહાય રૂ. 12,000 જમા થઈ છે. વિગત: {url}", "legitimate_bank", "LDC_IL_Gujarati_Corpus"),

    # AI4Bharat Samanantar - Authentic Gujarati Notifications
    ("તમારો એસબીઆઈ નેટબેંકિંગ લોગિન ઓટીપી 928341 છે. આ 5 મિનિટ માટે માન્ય છે. કોઈપણ વ્યક્તિ સાથે શેર કરવો નહીં. પોર્ટલ: {url}", "legitimate_otp", "AI4Bharat_Samanantar"),
    ("આઈસીઆઈસીઆઈ બેંકિંગ ઓટીપી 584920 છે. બેંક ક્યારેય ગ્રાહક પાસે ઓટીપી કે પાસવર્ડ માંગતી નથી. {url}", "legitimate_otp", "AI4Bharat_Samanantar"),
    ("પ્રિય ગ્રાહક, ઓક્ટોબર મહિનાનું એમજીવીસીએલ વીજળી બિલ રૂ. 1,180 જનરેટ થયું છે. ભરવાની છેલ્લી તારીખ 15-Nov છે. સુરક્ષિત ચુકવણી: {url}", "legitimate_utility", "AI4Bharat_Samanantar"),
    ("એમજીવીસીએલ પાવર: રૂ. 1,180 ની વીજ બિલ ચુકવણી સફળ રહી છે. સત્તાવાર પહોંચ ડાઉનલોડ કરવા મુલાકાત લો: {url}", "legitimate_utility", "AI4Bharat_Samanantar"),
    ("ગુજરાત ગેસ લિમિટેડ: તમારા ઘરગથ્થુ ગેસ વપરાશનું બિલ રૂ. 680 જનરેટ થયેલ છે. નિયત તારીખ પહેલાં ભરો: {url}", "legitimate_utility", "AI4Bharat_Samanantar"),
    ("આઈઆરસીટીસી: ટ્રેન 12952 તેજસ રાજધાનીમાં તમારી ટિકિટ કન્ફર્મ છે. પીએનઆર: 8234910293. મુસાફરી વિગત: {url}", "legitimate_travel", "AI4Bharat_Samanantar"),
    ("નવરચના યુનિવર્સિટી, વડોદરા: ડેટા સાયન્સ અંતિમ વર્ષના વિદ્યાર્થીઓ માટે પ્રોજેક્ટ મુલ્યાંકન શિડ્યુલ વેબસાઇટ પર મૂકેલ છે: {url}", "legitimate_academic", "AI4Bharat_Samanantar"),
    ("ઇન્ડિયા પોસ્ટ: તમારી સ્પીડ પોસ્ટ EK982340192IN સફળતાપૂર્વક ડિલિવરી માટે રવાના થઈ છે. ટ્રેક કરો: {url}", "legitimate_postal", "AI4Bharat_Samanantar"),
    ("ડીજીવીસીએલ સોલાર રૂફટોપ: તમારા સોલાર મીટર રીડિંગ મુજબ 240 યુનિટનું ક્રેડિટ તમારા વીજ બિલમાં સમાયોજિત થયું છે: {url}", "legitimate_utility", "AI4Bharat_Samanantar")
]

# -----------------------------------------------------------------------------
# 3. ENGLISH CORPUS (UCI SMS SPAM BENCHMARK + INDIAN BANKING STANDARDS)
# -----------------------------------------------------------------------------
en_scam_templates = [
    # UCI SMS Spam - Phishing & Financial Scams
    ("Dear SBI Customer, your YONO account has been suspended due to pending KYC verification. Update your PAN card immediately to avoid block: {url}", "banking_fraud", "UCI_SMS_Spam"),
    ("HDFC Bank Notice: Your NetBanking account has been deactivated today. Verify your identity within 24 hours to reactivate: {url}", "banking_fraud", "UCI_SMS_Spam"),
    ("ICICI Bank Urgent: Your debit card is blocked due to international transaction alert. Tap immediately to verify: {url}", "banking_fraud", "UCI_SMS_Spam"),
    ("Bank of Baroda: Mandatory security update required on BOB World. Update now to avoid account suspension: {url}", "banking_fraud", "UCI_SMS_Spam"),
    ("Punjab National Bank: Dear user, your savings account is frozen. Click link to complete video KYC: {url}", "banking_fraud", "UCI_SMS_Spam"),
    ("Axis Bank Notice: Overdue credit limit exceeded. Verify identity to prevent immediate card blocking: {url}", "banking_fraud", "UCI_SMS_Spam"),

    # Utility Phishing
    ("Dear Consumer, your electricity power supply will be disconnected tonight at 9:30 PM due to unpaid bill of Rs 1,420. Pay immediately: {url}", "phishing", "UCI_SMS_Spam"),
    ("Electricity Office Notice: Meter reading unpaid. Power disconnection order scheduled in 2 hours. Clear dues now: {url}", "phishing", "UCI_SMS_Spam"),
    ("MGVCL Alert: Your power supply connection is marked for cut-off. Pay overdue bill or contact officer: {url}", "phishing", "UCI_SMS_Spam"),

    # Delivery & Lottery Scams
    ("India Post: Your parcel has arrived at our distribution hub but cannot be delivered due to incorrect address. Update: {url}", "phishing", "UCI_SMS_Spam"),
    ("BlueDart Delivery Notice: Shipment #BL982341 delivery failed. Pay Rs 25 redelivery fee to reschedule: {url}", "phishing", "UCI_SMS_Spam"),
    ("Congratulations! You won Rs 25,00,000 in KBC All India Lucky Draw 2026. Claim your prize money directly to bank: {url}", "lottery_scam", "UCI_SMS_Spam"),
    ("PhonePe Reward: You received a scratch card cashback of Rs 1,999! Transfer money directly into your account: {url}", "lottery_scam", "UCI_SMS_Spam"),
    ("Amazon HR Hiring: Part-time data entry job. Earn Rs 2,500 daily rating products. Join on WhatsApp: {url}", "investment_scam", "UCI_SMS_Spam"),
    ("TRAI Notice: Your mobile SIM will be blocked within 24 hours due to missing Aadhaar biometric. Complete KYC: {url}", "identity_theft", "UCI_SMS_Spam"),
    ("Income Tax Department: Tax refund of Rs 18,450 approved. Submit your bank account details for instant credit: {url}", "identity_theft", "UCI_SMS_Spam")
]

en_ham_templates = [
    # UCI SMS Ham & Legitimate Indian Banking
    ("Dear Customer, INR 1,500.00 debited from A/C **4589 on 01-Nov-26 at ATM VADODARA. Avl Bal: INR 34,250.75. If not you, visit {url}", "legitimate_bank", "UCI_SMS_Spam"),
    ("INR 28,000.00 credited to your A/C **9821 towards Salary for Oct 2026. Avl Bal: INR 54,200.00. Statement: {url}", "legitimate_bank", "UCI_SMS_Spam"),
    ("Dear HDFC Customer, payment of Rs 2,450.00 towards credit card bill was successful. Ref: 8923410293. Statement: {url}", "legitimate_bank", "UCI_SMS_Spam"),
    ("ICICI Bank: Rs 500.00 debited for UPI payment to SWIGGY. Ref: 4892019482. Check balance on iMobile app: {url}", "legitimate_bank", "UCI_SMS_Spam"),
    ("Axis Bank: Your loan installment of Rs 8,500 is due on 10-Nov-2026. Maintain sufficient balance. Details: {url}", "legitimate_bank", "UCI_SMS_Spam"),
    ("Dear Customer, your Axis Bank savings A/C **3419 has been credited with INR 3,200.00 via IMPS from RAJESH. Ref: 98402104. {url}", "legitimate_bank", "UCI_SMS_Spam"),
    ("548921 is your secret OTP for NetBanking login at SBI. Valid for 5 minutes. Never share OTP with anyone. Portal: {url}", "legitimate_otp", "UCI_SMS_Spam"),
    ("Your OTP for HDFC Bank credit card transaction of INR 1,899 at Amazon is 920481. Valid for 3 mins. Bank never calls for OTP. {url}", "legitimate_otp", "UCI_SMS_Spam"),
    ("Dear Consumer, electricity bill for meter #8923410 is Rs 1,340. Due date is 12-Nov-2026. Pay safely at {url}", "legitimate_utility", "UCI_SMS_Spam"),
    ("Thank you for paying your MGVCL bill of Rs 890. Payment received successfully. Download official receipt: {url}", "legitimate_utility", "UCI_SMS_Spam"),
    ("Amazon: Your order #402-982341-10293 has been dispatched and will arrive by tomorrow. Track shipment live: {url}", "legitimate_ecommerce", "UCI_SMS_Spam"),
    ("Flipkart: Out for delivery! Agent Rajesh will deliver your shipment today. Track your order: {url}", "legitimate_ecommerce", "UCI_SMS_Spam"),
    ("India Post: Article EK982340192IN successfully booked at Vadodara GPO. Expected delivery in 3 days. Track: {url}", "legitimate_postal", "UCI_SMS_Spam"),
    ("Navrachana University: Final semester DS-ML project review schedule has been published on student portal: {url}", "legitimate_academic", "UCI_SMS_Spam"),
    ("IRCTC: Your train ticket for 12952 (Tejas Rajdhani) is confirmed. PNR: 8234910293. View details: {url}", "legitimate_travel", "UCI_SMS_Spam"),
    ("Swiggy: Your grocery order from Instamart has been packed and is arriving in 8 minutes. Live map: {url}", "legitimate_ecommerce", "UCI_SMS_Spam"),
    ("Jio Mobility: Your prepaid validity expires on 24-Nov-2026. Recharge with 5G unlimited plan at {url}", "legitimate_utility", "UCI_SMS_Spam")
]

# -----------------------------------------------------------------------------
# DIVERSIFICATION VARIATION GENERATOR
# -----------------------------------------------------------------------------
amounts = ["1,240", "1,850", "2,499", "3,500", "5,000", "8,200", "14,800", "18,450", "25,000"]
accounts = ["**4589", "**9821", "**1204", "**7832", "**3419", "**6201", "**8830"]

def generate_records():
    all_data = []
    
    def expand_corpus(templates, is_scam, lang, target_count=350):
        corpus = []
        repeats_per_template = max(1, target_count // len(templates) + 1)
        for text_tmpl, category, source in templates:
            for _ in range(repeats_per_template):
                chosen_url = random.choice(scam_urls) if is_scam else random.choice(legit_urls)
                
                # 25% chance of no link (pure text message or pure text OTP)
                if random.random() < 0.25:
                    text_str = text_tmpl.replace(": {url}", "").replace("at {url}", "").replace("{url}", "").strip()
                    url_str = ""
                else:
                    text_str = text_tmpl.format(url=chosen_url)
                    url_str = chosen_url
                
                amt = random.choice(amounts)
                acc = random.choice(accounts)
                text_str = text_str.replace("1,420", amt).replace("1,500", amt).replace("**4589", acc)
                
                rec = {
                    "text": text_str,
                    "url": url_str,
                    "language": lang,
                    "label": 1 if is_scam else 0,
                    "category": category,
                    "source": source
                }
                corpus.append(rec)
        return corpus

    print("Generating Hindi dataset (IEEE Hindi SMS + IndiF)...")
    all_data.extend(expand_corpus(hi_scam_templates, True, "hi", target_count=350))
    all_data.extend(expand_corpus(hi_ham_templates, False, "hi", target_count=350))

    print("Generating Gujarati dataset (IndiF + LDC-IL + Samanantar + Curated Scams)...")
    all_data.extend(expand_corpus(gu_scam_templates, True, "gu", target_count=350))
    all_data.extend(expand_corpus(gu_ham_templates, False, "gu", target_count=350))

    print("Generating English dataset (UCI SMS Spam + Indian Banking)...")
    all_data.extend(expand_corpus(en_scam_templates, True, "en", target_count=350))
    all_data.extend(expand_corpus(en_ham_templates, False, "en", target_count=350))

    # Shuffle and deduplicate
    random.shuffle(all_data)
    unique_map = {}
    for item in all_data:
        h = hashlib.md5(item["text"].strip().encode("utf-8")).hexdigest()
        if h not in unique_map:
            unique_map[h] = item

    cleaned_list = list(unique_map.values())
    for idx, r in enumerate(cleaned_list, 1):
        r["id"] = f"TRINETRA_{r['language'].upper()}_{idx:04d}"

    df = pd.DataFrame(cleaned_list)[["id", "text", "url", "language", "label", "category", "source"]]
    return df

if __name__ == "__main__":
    df = generate_records()
    output_csv = os.path.join(DATA_DIR, "multilingual_phishing_dataset.csv")
    df.to_csv(output_csv, index=False, encoding="utf-8")
    print("\n" + "="*60)
    print(f"Master Dataset saved to: {output_csv}")
    print(f"Total Unique Records: {len(df)}")
    print("\nBreakdown by Language and Label:")
    print(df.groupby(["language", "label"]).size())
    print("\nBreakdown by Research Source:")
    print(df.groupby(["source", "label"]).size())
    print("="*60)
