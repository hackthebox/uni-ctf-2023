import bcrypt, datetime, random

from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, Integer, String, Boolean, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base

from application.util.general import generate, generate_user, generate_email

Base = declarative_base()

class Users(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    verification_code = Column(String)
    verified = Column(Boolean, default=True)
    username = Column(String)
    password = Column(String)
    email = Column(String)


class Posts(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    username = Column(String)
    content = Column(String)
    market_link = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class Oauth2Codes(Base):
    __tablename__ = "oauth2_codes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    code = Column(String)
    client_id = Column(String)
    redirect_url = Column(String)
    exp = Column(DateTime(timezone=True))


class Database:
    def __init__(self):
        engine = create_engine(f"sqlite:///storage.db", echo=False)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        session = Session()
        self.session = session


    def migrate(self):
        products = [
            {
                "id": 1,
                "title": "Cryptocurrency Laundering Service",
                "content": "Safely convert your cryptocurrencies into untraceable digital assets, ensuring your financial privacy and security.",
                "price": "$5,000 - $15,000",
            },
            {
                "id": 2,
                "title": "Custom Malware Development",
                "content": "Tailor-made malware designed to meet your specific goals, whether it's data theft, espionage, or disruption.",
                "price": "Starting at $2,500",
            },
            {
                "id": 3,
                "title": "Stolen Data Packages",
                "content": "Gain access to vast databases of stolen user data, including login credentials, credit card numbers, and personal information.",
                "price": "$500 - $5,000",
            },
            {
                "id": 4,
                "title": "DDoS-for-Hire Services",
                "content": "Rent a botnet to launch powerful distributed denial-of-service attacks on targeted websites or services, causing disruption.",
                "price": "$5,000 - $15,000",
            },
            {
                "id": 5,
                "title": "Phishing Kit Bundle",
                "content": "Purchase a comprehensive package containing phishing tools, templates, and guidance for harvesting sensitive information.",
                "price": "$200",
            },
            {
                "id": 6,
                "title": "Zero-Day Exploits",
                "content": "Acquire undisclosed software vulnerabilities (zero-days) to exploit for malicious purposes, granting access to unpatched systems.",
                "price": "Starting at $10,000",
            },
            {
                "id": 7,
                "title": "Remote Access Trojans (RATs)",
                "content": "Covertly control and monitor remote computers using sophisticated Trojans that evade detection.",
                "price": "$1,000 - $5,000",
            },
            {
                "id": 8,
                "title": "Hacking Tutorials",
                "content": "Comprehensive guides, tutorials, and training materials for individuals looking to improve their hacking skills.",
                "price": "$50 - $500",
            },
            {
                "id": 9,
                "title": "Social Engineering Services",
                "content": "Hire skilled manipulators to execute social engineering attacks, such as impersonation or persuasion, for your specific needs.",
                "price": "Starting at $1,500",
            },
            {
                "id": 10,
                "title": "Credit Card Cloning Equipment",
                "content": "Purchase the necessary tools and guides to clone credit cards, enabling fraudulent transactions.",
                "price": "$500",
            },
            {
                "id": 11,
                "title": "Anonymous VPN and Proxy Services",
                "content": "Access encrypted connections and hide your IP address with reliable VPN and proxy services for anonymity.",
                "price": "$50",
            },
            {
                "id": 12,
                "title": "Counterfeit Documents",
                "content": "Obtain high-quality fake IDs, passports, and driver's licenses to assume new identities.",
                "price": "$300 - $1,000",
            },
            {
                "id": 13,
                "title": "Botnet Rental",
                "content": "Lease a network of compromised computers for various purposes, including spamming or launching attacks.",
                "price": "Starting at $100 per day",
            },
            {
                "id": 14,
                "title": "Ransomware-as-a-Service (RaaS)",
                "content": "Easily deploy ransomware attacks with support and infrastructure provided, allowing you to extort victims.",
                "price": "$1,000 per month",
            },
            {
                "id": 15,
                "title": "Hacker-for-Hire",
                "content": "Hire a skilled hacker to execute custom jobs, such as network infiltration or data exfiltration, tailored to your requirements.",
                "price": "starting at $5,000",
            }
        ]

        posts = [
            {
                "id": 16,
                "title": "New Exploit for Windows 10",
                "content": "Just stumbled upon a fresh exploit for Windows 10. Anyone interested in collaborating on some research? DM me!"
            },
            {
                "id": 17,
                "title": "The Art of Social Engineering",
                "content": "Let's discuss the psychology behind social engineering hacks. Share your best tactics and stories here."
            },
            {
                "id": 18,
                "title": "Ethical Hacking Beginner's Guide",
                "content": "I've compiled a comprehensive guide for newcomers interested in ethical hacking. Check it out and share your thoughts!"
            },
            {
                "id": 19,
                "title": "Dark Web Marketplace Updates",
                "content": "Looking for the latest updates on the dark web markets? Let's exchange info and stay ahead of the game."
            },
            {
                "id": 20,
                "title": "IoT Vulnerabilities",
                "content": "Discussing the latest Internet of Things (IoT) vulnerabilities and potential exploits. Who's up for some IoT hacking challenges?"
            },
            {
                "id": 21,
                "title": "Cracking Cryptocurrency Wallets",
                "content": "Sharing tips and tools for cracking cryptocurrency wallets. Let's find those hidden treasures!"
            },
            {
                "id": 22,
                "title": "VPN Recommendations",
                "content": "Need a reliable VPN for your activities? Share your recommendations and experiences here."
            },
            {
                "id": 23,
                "title": "Deep Web Exploration",
                "content": "Venturing into the depths of the deep web? Let's discuss what's lurking down there."
            },
            {
                "id": 24,
                "title": "Bypassing Firewalls 101",
                "content": "Tips and tricks for bypassing firewalls. Share your methods and success stories."
            },
            {
                "id": 25,
                "title": "Evolving Malware Techniques",
                "content": "Discussing the evolution of malware techniques and strategies. What's the future of malicious software?"
            },
            {
                "id": 26,
                "title": "CTF Challenge Announcement",
                "content": "Hosting a Capture The Flag (CTF) challenge soon. Stay tuned for details and prizes!"
            },
            {
                "id": 27,
                "title": "Anonymity Online",
                "content": "Let's talk about staying anonymous on the internet. VPNs, Tor, and more. Share your insights."
            },
            {
                "id": 28,
                "title": "Hacking for a Cause",
                "content": "Interested in hacktivism? Share your experiences and thoughts on using hacking skills for a noble cause."
            },
            {
                "id": 29,
                "title": "Reverse Engineering Challenges",
                "content": "Hosting a series of reverse engineering challenges. Join in, and let's crack some code!"
            },
            {
                "id": 30,
                "title": "Latest Security News",
                "content": "Stay updated on the latest cybersecurity news and breaches. Discuss recent incidents and their implications."
            }
        ]

        used_ids = []
        
        for i in range(25):
            username = "administrator" if i == 0 else generate_user()
            password = generate(32)
            email = generate_email()
            self.create_user(username, password, email)

            while True:
                random_number = random.randint(0, 2)

                if random_number == 0:
                    random_prod = random.choice(products)
                    if random_prod["id"] not in used_ids:
                        self.create_post(i, username, f"{random_prod['title']}, {random_prod['content']} Price {random_prod['price']}", f"/product/{random_prod['id']}")
                        used_ids.append(random_prod["id"])
                        break 
                else:
                    random_post = random.choice(posts)
                    if random_post["id"] not in used_ids:
                        self.create_post(i, username, random_post["content"])
                        used_ids.append(random_post["id"])
                        break


    def create_user(self, username, password, email):
        user = self.session.query(Users).filter(Users.username == username).first()
        if user:
            return False, None

        password_bytes = password.encode("utf-8")
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password_bytes, salt).decode()

        new_user = Users(username=username, password=password_hash, email=email)
        self.session.add(new_user)
        self.session.commit()

        return True, new_user.id


    def check_user(self, username, password):
        user = self.session.query(Users).filter(Users.username == username, Users.verified == True).first()

        if not user:
            return False, None
        
        password_bytes = password.encode("utf-8")
        password_encoded = user.password.encode("utf-8")
        matched = bcrypt.checkpw(password_bytes, password_encoded)
        
        if matched:
            return True, user.id
        
        return False, None


    def add_verification(self, user_id):
        verification_code = generate(12)
        self.session.query(Users).filter(Users.id == user_id).update({"verification_code": verification_code, "verified": False})
        self.session.commit()
        return verification_code


    def check_verification(self, verification_code):
        user_verified = self.session.query(Users).filter(Users.verification_code == verification_code).first()

        if not user_verified:
            return False

        self.session.query(Users).filter(Users.verification_code == verification_code).update({"verified": True})
        self.session.commit()
        return True


    def create_post(self, user_id, username, content, market_link=None):
        self.session.add(Posts(user_id=user_id, username=username, content=content, market_link=market_link))
        self.session.commit()
        return True


    def get_all_posts(self):
        posts = self.session.query(Posts).all()

        if not posts or len(posts) < 1:
            return False
        
        return posts[::-1]


    def create_auth_code(self, auth_code, client_id, redirect_url, exp):
        self.session.add(Oauth2Codes(code=auth_code, client_id=client_id, redirect_url=redirect_url, exp=exp))
        self.session.commit()
        return True


    def get_auth_code(self, auth_code):
        authorization_code = self.session.query(Oauth2Codes).filter(Oauth2Codes.code == auth_code).first()

        if not authorization_code:
            return False
        
        return authorization_code


    def del_auth_code(self, auth_code):
        self.session.query(Oauth2Codes).filter(Oauth2Codes.code == auth_code).delete()
        self.session.commit()
        return True