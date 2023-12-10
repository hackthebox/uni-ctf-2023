import bcrypt, datetime, random

from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, Integer, String, DateTime, create_engine
from sqlalchemy.ext.declarative import declarative_base

from application.util.general import generate

Base = declarative_base()

class Products(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer)
    username = Column(String)
    title = Column(String)
    description = Column(String)
    price = Column(String)
    image_link = Column(String)


class Orders(Base):
    __tablename__ = "orders"
    id = Column(Integer, primary_key=True)
    product_id = Column(String)
    user_id = Column(Integer)


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
                "user_id": 1,
                "username": "system",
                "title": "Cryptocurrency Laundering Service",
                "description": "Safely convert your cryptocurrencies into untraceable digital assets, ensuring your financial privacy and security.",
                "price": "$5,000 - $15,000",
                "image_link": "1.png"
            },
            {
                "user_id": 2,
                "username": "system",
                "title": "Custom Malware Development",
                "description": "Tailor-made malware designed to meet your specific goals, whether it's data theft, espionage, or disruption.",
                "price": "Starting at $2,500",
                "image_link": "2.png"
            },
            {
                "user_id": 3,
                "username": "system",
                "title": "Stolen Data Packages",
                "description": "Gain access to vast databases of stolen user data, including login credentials, credit card numbers, and personal information.",
                "price": "$500 - $5,000",
                "image_link": "3.png"
            },
            {
                "user_id": 4,
                "username": "system",
                "title": "DDoS-for-Hire Services",
                "description": "Rent a botnet to launch powerful distributed denial-of-service attacks on targeted websites or services, causing disruption.",
                "price": "$5,000 - $15,000",
                "image_link": "4.png"
            },
            {
                "user_id": 5,
                "username": "system",
                "title": "Phishing Kit Bundle",
                "description": "Purchase a comprehensive package containing phishing tools, templates, and guidance for harvesting sensitive information.",
                "price": "$200",
                "image_link": "5.png"
            },
            {
                "user_id": 6,
                "username": "system",
                "title": "Zero-Day Exploits",
                "description": "Acquire undisclosed software vulnerabilities (zero-days) to exploit for malicious purposes, granting access to unpatched systems.",
                "price": "Starting at $10,000",
                "image_link": "6.png"
            },
            {
                "user_id": 7,
                "username": "system",
                "title": "Remote Access Trojans (RATs)",
                "description": "Covertly control and monitor remote computers using sophisticated Trojans that evade detection.",
                "price": "$1,000 - $5,000",
                "image_link": "7.png"
            },
            {
                "user_id": 8,
                "username": "system",
                "title": "Hacking Tutorials",
                "description": "Comprehensive guides, tutorials, and training materials for individuals looking to improve their hacking skills.",
                "price": "$50 - $500",
                "image_link": "8.png"
            },
            {
                "user_id": 9,
                "username": "system",
                "title": "Social Engineering Services",
                "description": "Hire skilled manipulators to execute social engineering attacks, such as impersonation or persuasion, for your specific needs.",
                "price": "Starting at $1,500",
                "image_link": "9.png"
            },
            {
                "user_id": 10,
                "username": "system",
                "title": "Credit Card Cloning Equipment",
                "description": "Purchase the necessary tools and guides to clone credit cards, enabling fraudulent transactions.",
                "price": "$500",
                "image_link": "10.png"
            },
            {
                "user_id": 11,
                "username": "system",
                "title": "Anonymous VPN and Proxy Services",
                "description": "Access encrypted connections and hide your IP address with reliable VPN and proxy services for anonymity.",
                "price": "$50",
                "image_link": "11.png"
            },
            {
                "user_id": 12,
                "username": "system",
                "title": "Counterfeit Documents",
                "description": "Obtain high-quality fake IDs, passports, and driver's licenses to assume new identities.",
                "price": "$300 - $1,000",
                "image_link": "12.png"
            },
            {
                "user_id": 13,
                "username": "system",
                "title": "Botnet Rental",
                "description": "Lease a network of compromised computers for various purposes, including spamming or launching attacks.",
                "price": "Starting at $100 per day",
                "image_link": "13.png"
            },
            {
                "user_id": 14,
                "username": "system",
                "title": "Ransomware-as-a-Service (RaaS)",
                "description": "Easily deploy ransomware attacks with support and infrastructure provided, allowing you to extort victims.",
                "price": "$1,000 per month",
                "image_link": "14.png"
            },
            {
                "user_id": 15,
                "username": "system",
                "title": "Hacker-for-Hire",
                "description": "Hire a skilled hacker to execute custom jobs, such as network infiltration or data exfiltration, tailored to your requirements.",
                "price": "starting at $5,000",
                "image_link": "15.png"
            }
        ]

        for product in products:
            self.create_product(product["user_id"], product["username"], product["title"], product["description"], product["price"], product["image_link"])

        for i in range(5):
            self.create_order(random.randrange(1, 15), random.randrange(1, 15))

    
    def create_product(self, user_id, username, title, description, price, image_link):
        self.session.add(Products(user_id=user_id, username=username, title=title, description=description, price=price, image_link=image_link))
        self.session.commit()
        return True


    def get_all_products(self):
        products = self.session.query(Products).all()

        if not products or len(products) < 1:
            return False
        
        product_list = []
        for product in products:
            product = product.__dict__
            del product["_sa_instance_state"]
            product_list.append(product)

        return product_list[::-1]

    
    def get_product(self, product_id):
        product = self.session.query(Products).filter(Products.id == product_id).first()

        if not product:
            return False
        
        product = product.__dict__
        del product["_sa_instance_state"]
        
        return product


    def create_order(self, product_id, user_id):
        self.session.add(Orders(product_id=product_id, user_id=user_id))
        self.session.commit()
        return True


    def get_all_orders(self):
        orders = self.session.query(Orders).all()

        if not orders or len(orders) < 1:
            return False
        
        order_list = []
        for order in orders:
            order = order.__dict__
            del order["_sa_instance_state"]
            order_list.append(order)

        return order_list[::-1]