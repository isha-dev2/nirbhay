"""
High-Fidelity Multilingual Phishing & Safety Dataset Generator for Nirbhay
Generates 1500+ diverse, realistic samples across English, Hindi (Devanagari), and Gujarati.
Covers real-world Indian scam archetypes and verified legitimate communications.
"""
import random
import pandas as pd

random.seed(42)

# ==============================================================================
# 1. ENGLISH CORPUS (PHISHING & LEGITIMATE)
# ==============================================================================
en_phishing_templates = [
    # Banking & KYC
    ("Dear SBI Customer, your YONO account has been blocked due to pending KYC verification. Update your PAN immediately to avoid suspension: {url}", "bank_kyc"),
    ("HDFC Bank Alert: Your NetBanking access has been disabled today. Please verify your KYC details here to reactivate: {url}", "bank_kyc"),
    ("ICICI Notice: Your debit card is temporarily blocked due to unusual activity. Verify identity within 12 hours: {url}", "bank_kyc"),
    ("Axis Bank Urgent: Your savings account has reached credit limit. Submit updated KYC documents here: {url}", "bank_kyc"),
    ("Bank of Baroda: Your BOB World app needs mandatory security re-authentication. Complete now: {url}", "bank_kyc"),
    ("Punjab National Bank: Dear user, your PNB account will be suspended today. Click link to update KYC: {url}", "bank_kyc"),
    ("Kotak Mahindra Bank: Urgent update required on your 811 account. Avoid account freezing by updating here: {url}", "bank_kyc"),
    
    # Electricity & Utilities
    ("Dear Consumer, your electricity power supply will be disconnected tonight at 9:30 PM due to unpaid bill of Rs 1,420. Pay immediately: {url}", "electricity_bill"),
    ("Electricity Office Notice: Previous month meter bill not updated. Line will be disconnected within 2 hours. Clear dues now: {url}", "electricity_bill"),
    ("MGVCL Alert: Your power connection #948201 is marked for immediate cut-off. Pay overdue bill or contact officer: {url}", "electricity_bill"),
    ("UGVCL Power Department: Avoid power outage at your premises. Update meter reading and pay immediately: {url}", "electricity_bill"),
    ("Tata Power Notice: Bill payment overdue. Disconnection order generated. Settle dues immediately to cancel order: {url}", "electricity_bill"),

    # Parcel & Courier Delivery
    ("India Post: Your parcel has arrived at our distribution hub but cannot be delivered due to incomplete house number. Update address: {url}", "parcel_delivery"),
    ("BlueDart Delivery Notice: Shipment #BL982341 failed delivery. Pay Rs 25 redelivery fee to reschedule: {url}", "parcel_delivery"),
    ("DTDC Courier: Your package is held at customs warehouse. Please confirm recipient address and pay delivery charges: {url}", "parcel_delivery"),
    ("Delhivery Express: Delivery attempt failed for your parcel. Click link to verify delivery address within 24 hours: {url}", "parcel_delivery"),

    # Lottery, Prizes & Rewards
    ("Congratulations! You won Rs 25,00,000 in KBC All India Lucky Draw 2026. Claim your prize money directly to bank: {url}", "lottery_prize"),
    ("KBC Lucky Winner: Your mobile number has been selected for 1st prize of Rs 35,00,000. Complete registration: {url}", "lottery_prize"),
    ("Tata Motors Festival Lucky Draw: You won a brand new Tata Safari or cash prize of Rs 15 Lakh. Claim your voucher: {url}", "lottery_prize"),

    # Part-time Job & Task Fraud
    ("Work from home part-time job! Earn Rs 3,000 to Rs 8,000 daily by rating Google places and liking YouTube videos. Join now: {url}", "job_scam"),
    ("Amazon HR Hiring: Part-time data entry job. Earn Rs 2,500 daily. No prior experience required. Apply on WhatsApp: {url}", "job_scam"),
    ("Telegram Task Job: Get Rs 150 per task completed. Daily payout guaranteed via UPI. Click to start: {url}", "job_scam"),

    # UPI & Wallet Cashback Fraud
    ("PhonePe Reward: You received a scratch card cashback of Rs 1,999! Transfer money directly into your account: {url}", "upi_fraud"),
    ("Paytm Wallet Alert: Your wallet is expiring today. Claim your unused reward bonus of Rs 850 immediately: {url}", "upi_fraud"),
    ("Google Pay Festive Bonus: You have an unclaimed cashback voucher worth Rs 1,250. Click link to deposit: {url}", "upi_fraud"),

    # Government Scheme & Tax Refund
    ("PM Kisan Samman Nidhi: 18th installment of Rs 2,000 approved for release. Verify your Aadhaar card to receive amount: {url}", "govt_scheme"),
    ("Income Tax Department: Tax refund of Rs 18,450 has been approved. Submit your bank account details for instant credit: {url}", "tax_scam"),
    ("TRAI Notice: Your SIM card will be deactivated within 24 hours due to unverified Aadhaar link. Complete online KYC: {url}", "identity_theft"),
]

en_legitimate_templates = [
    # Legitimate Bank Alerts
    ("Dear Customer, INR 1,500.00 debited from A/C **4589 on 01-Nov-26 at ATM VADODARA. Avl Bal: INR 34,250.75. If not done by you, visit {url}", "legitimate_bank"),
    ("INR 25,000.00 credited to your A/C **9821 towards Salary for Oct 2026. Avl Bal: INR 68,400.00. Check statement at {url}", "legitimate_bank"),
    ("Dear HDFC Customer, payment of Rs 2,450.00 towards credit card bill was successful. Transaction Ref: 8923410293. Statement: {url}", "legitimate_bank"),
    ("ICICI Bank: Rs 500.00 debited for UPI payment to SWIGGY. Ref: 4892019482. Check balance on iMobile app or visit {url}", "legitimate_bank"),
    ("Axis Bank: Your loan installment of Rs 8,500 is due on 10-Nov-2026. Maintain sufficient balance in your account. Details: {url}", "legitimate_bank"),
    
    # Legitimate OTPs
    ("548921 is your secret OTP for NetBanking login at SBI. Valid for 5 minutes. Never share OTP with anyone, even bank staff. Portal: {url}", "legitimate_otp"),
    ("Your OTP for HDFC Bank credit card transaction of INR 1,899 at Amazon is 920481. Valid for 3 mins. Bank never calls for OTP. {url}", "legitimate_otp"),
    ("839201 is your verification code for ICICI NetBanking. If this was not initiated by you, immediately report at {url}", "legitimate_otp"),
    
    # Legitimate Utility & Bills
    ("Dear Consumer, your electricity bill for meter #8923410 is Rs 1,340. Due date is 12-Nov-2026. Pay safely at {url}", "legitimate_utility"),
    ("Thank you for paying your MGVCL bill of Rs 890. Payment received successfully. Download official receipt: {url}", "legitimate_utility"),
    ("Adani Gas: Your piped gas bill of Rs 620 for Oct 2026 is generated. Due date 15-Nov. Pay online at {url}", "legitimate_utility"),

    # Legitimate E-Commerce & Delivery
    ("Amazon: Your order #402-982341-10293 has been dispatched and will arrive by tomorrow. Track shipment live: {url}", "legitimate_ecommerce"),
    ("Flipkart: Out for delivery! Our agent Rajesh will deliver your shipment today. Track your order at {url}", "legitimate_ecommerce"),
    ("India Post: Article EK982340192IN successfully booked at Vadodara GPO. Expected delivery in 3 days. Track: {url}", "legitimate_postal"),
    ("Swiggy: Your delivery partner is on the way with your order from Honest Restaurant. Track in app: {url}", "legitimate_ecommerce"),

    # Legitimate Academic & Travel
    ("Navrachana University: Final semester DS-ML project review schedule has been published on the student portal: {url}", "legitimate_academic"),
    ("IRCTC: Your train ticket for 12952 (Tejas Rajdhani) is confirmed. PNR: 8234910293. View booking details at {url}", "legitimate_travel"),
    ("LIC Policy Alert: Annual premium of Rs 6,500 for policy #8923410 is due on 15-Nov-2026. Pay online: {url}", "legitimate_insurance"),
    ("Aadhaar authentication successful at CSC Vadodara for transaction 984021. If this was not you, lock biometrics at {url}", "legitimate_govt"),
]

# ==============================================================================
# 2. HINDI CORPUS (PHISHING & LEGITIMATE)
# ==============================================================================
hi_phishing_templates = [
    # Banking & KYC
    ("प्रिय एसबीआई ग्राहक, आपका बैंक खाता और योनो ऐप आज रात 9 बजे तक बंद कर दिया जाएगा क्योंकि आपका पैन कार्ड और केवाईसी अपडेट नहीं है। तुरंत लिंक पर क्लिक करके केवाईसी पूरा करें: {url}", "bank_kyc"),
    ("एचडीएफसी बैंक चेतावनी: आपका नेट बैंकिंग खाता निष्क्रिय कर दिया गया है। अपने खाते को पुनः सक्रिय करने के लिए पैन विवरण दर्ज करें: {url}", "bank_kyc"),
    ("आईसीआईसीआई बैंक सूचना: आपके खाते से संदिग्ध लेनदेन दर्ज हुआ है। लेनदेन निरस्त करने और खाता सुरक्षित करने के लिए यहां लॉगिन करें: {url}", "bank_kyc"),
    ("बैंक ऑफ बड़ौदा: आपका डेबिट कार्ड तुरंत ब्लॉक कर दिया गया है। कार्ड अनब्लॉक करने के लिए ऑनलाइन सत्यापन पूरा करें: {url}", "bank_kyc"),
    ("पीएनबी अलर्ट: प्रिय ग्राहक, आपका बचत खाता सुरक्षा कारणों से फ्रीज कर दिया गया है। पुनः चालू करने के लिए दस्तावेज जमा करें: {url}", "bank_kyc"),

    # Electricity & Utilities
    ("प्रिय उपभोक्ता, आपके बिजली बिल का भुगतान न होने के कारण आज रात 9:30 बजे बिजली कनेक्शन काट दिया जाएगा। तुरंत बिल भरें: {url}", "electricity_bill"),
    ("बिजली विभाग सूचना: आपके मीटर का पिछला बिल बाकी है। बिजली कटने से बचने के लिए तुरंत इस पोर्टल पर भुगतान करें: {url}", "electricity_bill"),
    ("विद्युत निगम जरूरी सूचना: उपभोक्ता संख्या 923410 का बिजली कनेक्शन आज रात बंद किया जाएगा। लाइनमैन से बचने हेतु तुरंत भुगतान करें: {url}", "electricity_bill"),
    ("बिजली मीटर अलर्ट: मीटर रीडिंग अपडेट न होने से कनेक्शन डिस्कनेक्शन सूची में डाला गया है। तुरंत रसीद अपडेट करें: {url}", "electricity_bill"),

    # Parcel & Courier
    ("इंडिया पोस्ट: आपका पार्सल गलत पते के कारण डिलीवरी केंद्र पर अटका हुआ है। 24 घंटे के भीतर पता अपडेट करें और 25 रुपये शुल्क दें: {url}", "parcel_delivery"),
    ("भारतीय डाक सूचना: डाक पार्सल का पता अधूरा है। रीडिलीवरी शुल्क जमा करें और नया पता भरें: {url}", "parcel_delivery"),
    ("ब्लूडार्ट कूरियर: आपका पार्सल डिलीवर नहीं हो सका। पता सत्यापित करें ताकि डिलीवरी की जा सके: {url}", "parcel_delivery"),

    # Lottery & Cashback
    ("बधाई हो! आपने कौन बनेगा करोड़पति (KBC) में 25 लाख रुपये की लॉटरी जीती है। अपनी इनाम राशि बैंक खाते में पाने के लिए क्लिक करें: {url}", "lottery_prize"),
    ("केबीसी लकी ड्रॉ 2026: आपका नंबर प्रथम पुरस्कार हेतु चुना गया है। मैनेजर से संपर्क करें और पुरस्कार राशि का दावा करें: {url}", "lottery_prize"),
    ("फोनपे कैशबैक: आपको रु 999 का लकी स्क्रैच कार्ड मिला है। अपनी कैशबैक राशि सीधे बैंक खाते में प्राप्त करने के लिए क्लिक करें: {url}", "upi_fraud"),
    ("पेटीएम वॉलेट अलर्ट: आपकी वॉलेट सीमा समाप्त हो चुकी है। बिना शुल्क तुरंत पूर्ण केवाईसी अपडेट करें: {url}", "upi_fraud"),
    ("गूगल पे रिवॉर्ड: आपके खाते में रु 1,500 का रिवॉर्ड कूपन आया है। राशि ट्रांसफर करने के लिए अनलॉक करें: {url}", "upi_fraud"),

    # Jobs & Schemes
    ("घर बैठे पार्ट टाइम जॉब! यूट्यूब वीडियो लाइक करके और होटल रिव्यू देकर रोजाना 3000 से 5000 रुपये कमाएं। तुरंत जुड़ें: {url}", "job_scam"),
    ("पीएम किसान सम्मान निधि: 2000 रुपये की अगली किस्त आपके खाते में भेजी जा रही है। अपना आधार कार्ड नंबर सत्यापित करें: {url}", "govt_scheme"),
    ("आयकर विभाग: आपके वित्तीय वर्ष का 18,200 रुपये का रिफंड स्वीकृत हो गया है। खाते की पुष्टि करने के लिए लिंक खोलें: {url}", "tax_scam"),
    ("अति आवश्यक: आपका सिम कार्ड 24 घंटे में ब्लॉक हो जाएगा। टेलीकॉम वेरिफिकेशन पूरा करने के लिए तुरंत क्लिक करें: {url}", "identity_theft"),
]

hi_legitimate_templates = [
    # Legitimate Bank Alerts
    ("प्रिय ग्राहक, आपके खाता संख्या **4589 से रु 1,500.00 का एटीएम आहरण सफल रहा। शेष राशि रु 34,250.75 है। आधिकारिक पोर्टल: {url}", "legitimate_bank"),
    ("आपके खाते में मासिक वेतन के रु 42,000.00 जमा कर दिए गए हैं। बैलेंस जांचने के लिए बैंक की आधिकारिक ऐप देखें: {url}", "legitimate_bank"),
    ("एचडीएफसी बैंक: रु 850.00 का यूपीआई भुगतान सफल रहा। यदि यह आपने नहीं किया तो कस्टमर केयर से संपर्क करें: {url}", "legitimate_bank"),
    ("आईसीआईसीआई बैंक: आपके क्रेडिट कार्ड का बिल रु 3,400 नियत तिथि 15-नवंबर से पहले भरें। विवरण: {url}", "legitimate_bank"),

    # Legitimate OTPs
    ("एसबीआई नेटबैंकिंग लॉगिन के लिए आपका ओटीपी 749201 है। यह 5 मिनट के लिए मान्य है। किसी के साथ शेयर न करें। पोर्टल: {url}", "legitimate_otp"),
    ("एचडीएफसी बैंक: ऑनलाइन खरीदारी के लिए आपका गुप्त ओटीपी 819230 है। सतर्क रहें, बैंक कभी फोन पर ओटीपी नहीं मांगता। {url}", "legitimate_otp"),
    ("नेटबैंकिंग पासवर्ड बदलने हेतु ओटीपी 491028 है। बैंक कर्मचारी कभी आपसे ओटीपी नहीं पूछते। सुरक्षित रहें: {url}", "legitimate_otp"),

    # Legitimate Utility & Deliveries
    ("प्रिय उपभोक्ता, आपके बिजली मीटर का बिल रु 1,280 है। देय तिथि 15-नवंबर है। सुरक्षित भुगतान के लिए आधिकारिक साइट देखें: {url}", "legitimate_utility"),
    ("बिजली विभाग: आपका रु 950 का बिल भुगतान सफलतापूर्वक प्राप्त हो गया है। रसीद देखने के लिए आधिकारिक पोर्टल पर जाएं: {url}", "legitimate_utility"),
    ("अमेज़न: आपका ऑर्डर सफलतापूर्वक भेज दिया गया है और कल दोपहर तक पहुंचेगा। ट्रैकिंग विवरण यहां देखें: {url}", "legitimate_ecommerce"),
    ("फ्लिपकार्ट: आपका पैकेज डिलीवरी के लिए तैयार है। डिलीवरी बॉय आज संपर्क करेगा। विवरण देखें: {url}", "legitimate_ecommerce"),
    ("भारतीय डाक: आपका पंजीकृत पत्र गंतव्य डाकघर पहुंच गया है। ऑनलाइन ट्रैकिंग के लिए आधिकारिक पोर्टल देखें: {url}", "legitimate_postal"),

    # Legitimate Education & Travel
    ("नवरचना यूनिवर्सिटी: डाटा साइंस एंड मशीन लर्निंग विषय की अंतिम परीक्षा समय सारिणी घोषित। पोर्टल देखें: {url}", "legitimate_academic"),
    ("आईआरसीटीसी: आपकी ट्रेन टिकट की बुकिंग सफल रही। पीएनआर 8492019384 है। ई-टिकट डाउनलोड करें: {url}", "legitimate_travel"),
    ("एलआईसी प्रीमियम सूचना: आपकी जीवन बीमा पॉलिसी का वार्षिक प्रीमियम 10 नवंबर तक देय है। आधिकारिक पोर्टल: {url}", "legitimate_insurance"),
]

# ==============================================================================
# 3. GUJARATI CORPUS (PHISHING & LEGITIMATE)
# ==============================================================================
gu_phishing_templates = [
    # Banking & KYC
    ("પ્રિય SBI ગ્રાહક, તમારું બેંક એકાઉન્ટ KYC અપડેટ ન હોવાથી સ્થગિત કરવામાં આવશે. સેવાઓ ચાલુ રાખવા માટે હમણાં જ લિંક પર ક્લિક કરી પાન કાર્ડ વેરિફાઈ કરો: {url}", "bank_kyc"),
    ("HDFC બેંક સૂચના: તમારું નેટ બેંકિંગ બ્લોક કરવામાં આવ્યું છે. 24 કલાકમાં ચાલુ કરવા માટે તાત્કાલિક વિગતો અપડેટ કરો: {url}", "bank_kyc"),
    ("બેંક ઓફ બરોડા એલર્ટ: અનધિકૃત વ્યવહાર અટકાવવા માટે તમારા એકાઉન્ટનું ઓનલાઇન વેરિફિકેશન પૂર્ણ કરો: {url}", "bank_kyc"),
    ("ICICI બેંક એલર્ટ: તમારું એટીએમ કાર્ડ સુરક્ષા કારણોસર સસ્પેન્ડ થયું છે. તાત્કાલિક રી-એક્ટિવેટ કરવા માટે ક્લિક કરો: {url}", "bank_kyc"),
    ("PNB બેંક નોટિસ: તમારા બચત ખાતાનું કેવાયસી બાકી છે. ખાતું ફ્રીઝ થવાથી બચવા પાન કાર્ડ જોડો: {url}", "bank_kyc"),

    # Electricity & Utilities
    ("પ્રિય ગ્રાહક, તમારા પાછલા મહિનાનું વીજળી બિલ અપડેટ ન હોવાથી આજે રાત્રે 9:30 વાગ્યે વીજ કનેક્શન કાપી નાખવામાં આવશે. તાત્કાલિક સંપર્ક કરો અથવા બિલ ભરો: {url}", "electricity_bill"),
    ("MGVCL વીજળી બિલ નોટિસ: તમારા મીટરનું બાકી બિલ તાત્કાલિક ભરો નહીંતર કનેક્શન કાયમી ધોરણે કપાઈ જશે. ચૂકવણી માટે લિંક: {url}", "electricity_bill"),
    ("UGVCL પાવર એલર્ટ: વીજળી કટ થવાથી બચવા માટે તાત્કાલિક ગ્રાહક નંબર પર બિલ ચૂકવો: {url}", "electricity_bill"),
    ("DGVCL વીજ વિભાગ: તમારું મીટર બિલ સિસ્ટમમાં જમા થયું નથી. લાઇન કપાત ટાળવા તરત જ ઓનલાઇન ક્લિયર કરો: {url}", "electricity_bill"),

    # Parcel & Courier
    ("ઈન્ડિયા પોસ્ટ: સરનામું અધૂરું હોવાથી તમારું પાર્સલ વેરહાઉસમાં અટકી ગયું છે. 24 કલાકમાં ડિલિવરી મેળવવા માટે એડ્રેસ અપડેટ કરો: {url}", "parcel_delivery"),
    ("ભારતીય ટપાલ વિભાગ: તમારા પાર્સલની પુનઃ ડિલિવરી માટે રૂ. 25 ચાર્જ ભરો અને નવું સરનામું મોકલો: {url}", "parcel_delivery"),
    ("બ્લૂડાર્ટ કુરિયર એલર્ટ: તમારા ઘરનું સરનામું ચકાસવા માટે લિંક પર ક્લિક કરો: {url}", "parcel_delivery"),

    # Lottery, Rewards & Cashback
    ("અભિનંદન! તમે KBC લકી ડ્રોમાં રૂ. 25,00,000 નું રોકડ ઈનામ જીત્યા છો. તમારા ખાતામાં રકમ જમા કરાવવા માટે હમણાં જ ક્લેમ કરો: {url}", "lottery_prize"),
    ("KBC લકી વિનર 2026: તમારો મોબાઈલ નંબર પ્રથમ ઈનામ માટે પસંદ થયો છે. રકમ મેળવવા માટે રજીસ્ટ્રેશન કરો: {url}", "lottery_prize"),
    ("PhonePe કેશબેક રિવોર્ડ: તમને રૂ. 999 નું સ્ક્રેચ કાર્ડ મળ્યું છે! રકમ સીધા તમારા બેંક ખાતામાં જમા કરવા માટે હમણાં જ ક્લેમ કરો: {url}", "upi_fraud"),
    ("Paytm વૉલેટ ચેતવણી: તમારું KYC પૂર્ણ ન હોવાથી વૉલેટ બંધ થશે. કોઈ ચાર્જ વગર તુરંત KYC કરો: {url}", "upi_fraud"),
    ("Google Pay ઈનામ: તમને મળ્યું છે રૂ. 1,450 નું કેશબેક. સીધા બેંકમાં ટ્રાન્સફર કરવા માટે ઓપન કરો: {url}", "upi_fraud"),

    # Jobs & Schemes
    ("ઘરે બેઠા પાર્ટ-ટાઈમ કામ કરીને દરરોજ 3,000 થી 5,000 રૂપિયા કમાઓ! સરળ યૂટ્યુબ ટાસ્ક પૂરા કરી કમાણી કરો. હમણાં જ જોડાઓ: {url}", "job_scam"),
    ("પીએમ કિસાન યોજના: તમારા ખાતામાં રૂ. 2,000 ની સહાય જમા થઈ છે. ખાતાની ચકાસણી કરવા અને રકમ મેળવવા આધાર લિંક કરો: {url}", "govt_scheme"),
    ("આવકવેરા વિભાગ: તમારા નામે રૂ. 16,500 નું ટેક્સ રિફંડ મંજૂર થયું છે. તમારા બેંક ખાતામાં મેળવવા માટે વિગતો ભરો: {url}", "tax_scam"),
    ("ખાસ સૂચના: તમારું સિમ કાર્ડ આધાર સાથે લિંક ન હોવાથી બ્લોક થશે. ચાલુ રાખવા માટે તાત્કાલિક વેરિફિકેશન કરો: {url}", "identity_theft"),
]

gu_legitimate_templates = [
    # Legitimate Bank Alerts
    ("પ્રિય ગ્રાહક, તમારા ખાતામાંથી રૂ. 1,500.00 ATM વડોદરા ખાતે ડેબિટ થયા છે. ઉપલબ્ધ બેલેન્સ રૂ. 34,250.75 છે. જો આ વ્યવહાર તમે ન કર્યો હોય તો સંપર્ક કરો: {url}", "legitimate_bank"),
    ("તમારા ખાતામાં માસિક પગારના રૂ. 38,000.00 જમા થયા છે. વિગતવાર સ્ટેટમેન્ટ માટે સત્તાવાર પોર્ટલની મુલાકાત લો: {url}", "legitimate_bank"),
    ("બેંક ઓફ બરોડા: રૂ. 1,200 ની ખરીદી માટે કાર્ડ સફળતાપૂર્વક વપરાયું. સત્તાવાર પોર્ટલ: {url}", "legitimate_bank"),
    ("HDFC બેંક: તમારા ક્રેડિટ કાર્ડનું બિલ રૂ. 2,800 છેલ્લી તારીખ 12-નવેમ્બર પહેલા ભરો. વિગત: {url}", "legitimate_bank"),

    # Legitimate OTPs
    ("નેટબેંકિંગ લોગિન માટે તમારો ગુપ્ત OTP 928341 છે. આ 5 મિનિટ માટે માન્ય છે. સુરક્ષા માટે કોઈની સાથે શેર કરશો નહીં: {url}", "legitimate_otp"),
    ("બેંક ઓફ બરોડા: રૂ. 1,200 ની ઓનલાઇન ખરીદી માટે તમારો OTP 481920 છે. બેંક ક્યારેય ફોન પર OTP માંગતી નથી. સત્તાવાર સાઇટ: {url}", "legitimate_otp"),
    ("એસબીઆઈ પાસવર્ડ રીસેટ માટે તમારો વેરિફિકેશન કોડ 391024 છે. કોઈને આપશો નહીં: {url}", "legitimate_otp"),

    # Legitimate Utility & Delivery
    ("પ્રિય ગ્રાહક, તમારા વીજળી જોડાણનું બિલ રૂ. 1,150 છે. છેલ્લી તારીખ 12-નવેમ્બર છે. ઓનલાઇન બિલ ભરવા માટે મુલાકાત લો: {url}", "legitimate_utility"),
    ("MGVCL: તમારા કનેક્શનનું રૂ. 1,020 નું બિલ સફળતાપૂર્વક ચૂકવાઈ ગયું છે. રસીદ ડાઉનલોડ કરવા માટે સત્તાવાર લિંક: {url}", "legitimate_utility"),
    ("એમેઝોન: તમારો ઓર્ડર #402-18293 સફળતાપૂર્વક ડિસ્પેચ થયો છે અને આવતીકાલે મળશે. ટ્રેકિંગ માટે: {url}", "legitimate_ecommerce"),
    ("ફ્લિપકાર્ટ: તમારો પાર્સલ ડિલિવરી બોય સાથે નીકળી ગયો છે. સાંજે 5 વાગ્યા પહેલા ડિલિવરી થશે. ટ્રેક કરો: {url}", "legitimate_ecommerce"),
    ("ભારતીય ટપાલ વિભાગ: તમારી સ્પીડ પોસ્ટ વડોદરા પહોંચી ગઈ છે. સત્તાવાર ટ્રેકિંગ માટે પોર્ટલ જુઓ: {url}", "legitimate_postal"),

    # Legitimate Education & Travel
    ("નવરચના યુનિવર્સિટી: સેમેસ્ટર એન્ડ પ્રોજેક્ટ પ્રેઝન્ટેશન આવતીકાલે સવારે 10 વાગ્યે શરૂ થશે. વિગતો: {url}", "legitimate_academic"),
    ("IRCTC: તમારી રેલવે ટિકિટ કન્ફર્મ થઈ ગઈ છે. PNR નંબર 8492018491 છે. ઈ-ટિકિટ ડાઉનલોડ કરવા મુલાકાત લો: {url}", "legitimate_travel"),
    ("LIC પોલિસી નોટિસ: તમારા પ્રીમિયમની ચૂકવણી સફળતાપૂર્વક થઈ ગઈ છે. રસીદ માટે સત્તાવાર સાઇટ જુઓ: {url}", "legitimate_insurance"),
]

# ==============================================================================
# URL PATTERNS & SYNTHESIS
# ==============================================================================
phishing_domain_components = [
    "sbi-kyc-verify-portal", "sbi-quick-kyc-update", "hdfc-netbanking-secure-login",
    "icici-alert-verification", "mgvcl-bill-pay-online", "electricity-urgent-bill-pay",
    "indiapost-parcel-address-update", "kbc-lucky-winner-claim", "wfh-parttime-earn-daily",
    "phonepe-cashback-reward-claim", "paytm-kyc-verification-instant", "pmkisan-aadhaar-link-service",
    "secure-banking-portal-india", "online-kyc-update-desk", "pan-link-aadhaar-portal",
    "refund-incometax-gov-online", "fast-cashback-phonepe-app", "bob-netbanking-verify",
    "axis-netbanking-portal", "pnb-one-kyc-desk", "ugvcl-light-bill-desk", "tatapower-bill-online"
]

phishing_tlds = [".top", ".xyz", ".click", ".club", ".live", ".buzz", ".work", ".site", ".support", ".cfd", ".icu", ".online"]

phishing_paths = [
    "/login.php", "/kyc-update/index.html", "/verify-account.action", "/claim-reward/user",
    "/bill-pay/urgent", "/tracking/address-confirm", "/secure-auth/step1", "/pay-fine.asp",
    "/aadhaar-link/confirm", "/redeem-coupon/pay", "/unblock-account/form"
]

legitimate_urls = [
    "https://onlinesbi.sbi", "https://www.hdfcbank.com", "https://www.icicibank.com",
    "https://www.bankofbaroda.in", "https://www.axisbank.com", "https://www.pnbindia.in",
    "https://www.mgvcl.com", "https://uppcl.org", "https://www.indiapost.gov.in",
    "https://www.amazon.in/orders", "https://www.flipkart.com", "https://nuv.ac.in",
    "https://www.irctc.co.in", "https://licindia.in", "https://cybercrime.gov.in",
    "https://www.incometax.gov.in", "https://uidai.gov.in", "https://www.phonepe.com",
    "https://paytm.com", "https://pmkisan.gov.in"
]

def generate_phishing_url():
    prob = random.random()
    if prob < 0.18:
        # IP address URL (blatant phishing)
        ip = f"{random.randint(100, 220)}.{random.randint(10, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
        port = random.choice([80, 8080, 8000, 8888])
        return f"http://{ip}:{port}{random.choice(phishing_paths)}"
    elif prob < 0.40:
        # Multi-subdomain with brand spoof
        sub = random.choice(["update", "secure", "verify", "banking", "online", "login", "portal"])
        brand = random.choice(["sbi", "hdfc", "mgvcl", "phonepe", "indiapost", "kbc", "axis", "bob"])
        tld = random.choice(phishing_tlds)
        return f"http://{sub}.{brand}-verification{tld}{random.choice(phishing_paths)}?token={random.randint(10000, 99999)}"
    else:
        domain = random.choice(phishing_domain_components)
        tld = random.choice(phishing_tlds)
        path = random.choice(phishing_paths)
        return f"http://{domain}{tld}{path}?ref={random.randint(1000, 9999)}"

def generate_legit_url():
    base = random.choice(legitimate_urls)
    if random.random() < 0.6:
        suffix = random.choice(["/portal", "/login", "/home", "/track", "/support", "/services", "/pay-online", "/account"])
        return f"{base}{suffix}"
    return base

# ==============================================================================
# DATASET GENERATION PIPELINE (1500+ SAMPLES)
# ==============================================================================
def generate_dataset():
    records = []
    rec_id = 1

    # 1. English: 250 Phishing + 250 Legitimate = 500 samples
    for i in range(250):
        tmpl, cat = random.choice(en_phishing_templates)
        url = generate_phishing_url()
        text = tmpl.format(url=url)
        records.append({"id": rec_id, "text": text, "url": url, "language": "en", "label": 1, "category": cat})
        rec_id += 1

    for i in range(250):
        tmpl, cat = random.choice(en_legitimate_templates)
        url = generate_legit_url()
        text = tmpl.format(url=url)
        records.append({"id": rec_id, "text": text, "url": url, "language": "en", "label": 0, "category": cat})
        rec_id += 1

    # 2. Hindi: 250 Phishing + 250 Legitimate = 500 samples
    for i in range(250):
        tmpl, cat = random.choice(hi_phishing_templates)
        url = generate_phishing_url()
        text = tmpl.format(url=url)
        records.append({"id": rec_id, "text": text, "url": url, "language": "hi", "label": 1, "category": cat})
        rec_id += 1

    for i in range(250):
        tmpl, cat = random.choice(hi_legitimate_templates)
        url = generate_legit_url()
        text = tmpl.format(url=url)
        records.append({"id": rec_id, "text": text, "url": url, "language": "hi", "label": 0, "category": cat})
        rec_id += 1

    # 3. Gujarati: 250 Phishing + 250 Legitimate = 500 samples
    for i in range(250):
        tmpl, cat = random.choice(gu_phishing_templates)
        url = generate_phishing_url()
        text = tmpl.format(url=url)
        records.append({"id": rec_id, "text": text, "url": url, "language": "gu", "label": 1, "category": cat})
        rec_id += 1

    for i in range(250):
        tmpl, cat = random.choice(gu_legitimate_templates)
        url = generate_legit_url()
        text = tmpl.format(url=url)
        records.append({"id": rec_id, "text": text, "url": url, "language": "gu", "label": 0, "category": cat})
        rec_id += 1

    # 4. Realistic Boundary / Edge Cases (Stealth phishing, phone scams, urgent legitimate alerts)
    edge_cases = [
        # Stealth Phishing (Neutral text, malicious link)
        ("Good morning, your requested bank account statement is ready for download: {url}", "en", 1, "stealth_phishing"),
        ("Dear customer, please review your updated terms of service here: {url}", "en", 1, "stealth_phishing"),
        ("नमस्ते, आपके खाते का विवरण तैयार है। कृपया यहाँ देखें: {url}", "hi", 1, "stealth_phishing"),
        ("પ્રિય ગ્રાહક, તમારા દસ્તાવેજ તૈયાર છે. ચકાસવા માટે અહીં જુઓ: {url}", "gu", 1, "stealth_phishing"),

        # Urgent Legitimate (Urgent text, authentic domain)
        ("URGENT: Transaction of INR 10,000 on your HDFC card. If NOT done by you, immediately lock card at https://www.hdfcbank.com", "en", 0, "legitimate_urgent"),
        ("अति आवश्यक: आपके बैंक खाते से रु 15,000 कटे हैं। यदि यह आपने नहीं किया तो तुरंत https://onlinesbi.sbi पर कार्ड ब्लॉक करें।", "hi", 0, "legitimate_urgent"),
        ("તાત્કાલિક: તમારા ખાતામાંથી રૂ. 12,000 ડેબિટ થયા છે. જો તમે નથી કર્યું તો કાર્ડ તરત બ્લોક કરો: https://www.bankofbaroda.in", "gu", 0, "legitimate_urgent"),
        ("Immediate action needed: Electricity scheduled maintenance tonight from 2AM to 4AM in Vadodara area. See https://www.mgvcl.com", "en", 0, "legitimate_urgent"),
        ("जरूरी सूचना: बिजली लाइन मरम्मत कार्य हेतु कल सुबह 10 से 12 बजे तक आपूर्ति बाधित रहेगी। https://uppcl.org", "hi", 0, "legitimate_urgent"),
        ("તાકીદની જાણ: વીજળી લાઇન રિપેરિંગ માટે કાલે સવારે પુરવઠો બંધ રહેશે. https://www.mgvcl.com", "gu", 0, "legitimate_urgent"),

        # Phone-only Scams (No URL, call fraud numbers)
        ("URGENT: Your SBI bank account will be blocked today. Immediately call our manager at 9823491029 to avoid permanent suspension.", "en", 1, "phone_phishing"),
        ("Dear User, your electricity will be disconnected tonight at 9 PM. Call junior engineer at 9876543210 urgently to resolve.", "en", 1, "phone_phishing"),
        ("चेतावनी: आपका बिजली कनेक्शन तुरंत काटा जा रहा है। बहाली के लिए हमारे अधिकारी को 9823019283 पर कॉल करें।", "hi", 1, "phone_phishing"),
        ("एसबीआई खाताधारक ध्यान दें: आपका खाता सीज कर दिया गया है। मैनेजर से 9123847192 पर व्हाट्सएप द्वारा संपर्क करें।", "hi", 1, "phone_phishing"),
        ("તાત્કાલિક નોટિસ: તમારા કનેક્શન આજે કાપવામાં આવશે. બિલ ક્લિયર કરવા માટે આ નંબર 9723019284 પર સંપર્ક કરો.", "gu", 1, "phone_phishing"),
        ("બેંક ગ્રાહક સાવધાન: તમારું ખાતું ફ્રીઝ થયું છે. મુશ્કેલી નિવારણ માટે અમારા એક્ઝિક્યુટિવ 9823401928 ને ફોન કરો.", "gu", 1, "phone_phishing"),

        # Pure Text Legitimate (No URL)
        ("Dear SBI Customer, your A/C **4589 credited with Rs 5,000 via IMPS. Avl Bal: Rs 42,100.", "en", 0, "legitimate_bank"),
        ("Your OTP for Swiggy food delivery is 482910. Do not disclose to delivery partner until food arrives.", "en", 0, "legitimate_otp"),
        ("प्रिय ग्राहक, आपके खाते में रु 2,500 जमा किए गए हैं। कुल शेष रु 18,900 है।", "hi", 0, "legitimate_bank"),
        ("जोमैटो डिलीवरी के लिए आपका ओटीપી 391024 है। भोजन मिलने पर ही बताएं।", "hi", 0, "legitimate_otp"),
        ("પ્રિય ગ્રાહક, તમારા ખાતામાં રૂ. 4,000 જમા થયા છે. ઉપલબ્ધ બેલેન્સ રૂ. 22,150 છે.", "gu", 0, "legitimate_bank"),
        ("ઝોમેટો ફૂડ ડિલિવરી માટે તમારો OTP 592810 છે. ફૂડ મળ્યા પછી જ શેર કરવો.", "gu", 0, "legitimate_otp"),
    ]

    for tmpl, lang, lbl, cat in edge_cases:
        for rep in range(4):
            if "{url}" in tmpl:
                url = generate_phishing_url() if lbl == 1 else generate_legit_url()
                txt = tmpl.format(url=url)
            else:
                url = ""
                txt = tmpl
                if "982" in txt and rep > 0:
                    txt = txt.replace("982", f"9{random.randint(10, 99)}")
            
            records.append({"id": rec_id, "text": txt, "url": url, "language": lang, "label": lbl, "category": cat})
            rec_id += 1

    df = pd.DataFrame(records)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    df.to_csv("data/multilingual_phishing_dataset.csv", index=False, encoding="utf-8")
    print(f"Dataset generated successfully! Total records: {len(df)}")
    print(f"Language breakdown:\n{df['language'].value_counts()}")
    print(f"Class breakdown:\n{df['label'].value_counts()}")

if __name__ == "__main__":
    generate_dataset()
