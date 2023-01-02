from sqlalchemy import create_engine, Column, Integer, String, Float, Enum, select
from sqlalchemy.orm import declarative_base, sessionmaker
import enum

Base = declarative_base()


class ConclEnum(enum.Enum):
    honeypot = 1
    not_honeypot = 0


class Conslusions(Base):
    __tablename__ = 'Result data'
    ip = Column(String, primary_key=True)
    not_honeypot = Column(Integer)
    honeypot = Column(Integer)
    conclusion = Column(Enum(ConclEnum))


class Statistics(Base):
    __tablename__ = 'Statistics'
    id = Column(Integer, primary_key=True)
    ip = Column(String)
    ping_time = Column(Float)
    probability = Column(Float)


class database:
    # def __init__(self, limit:float, path: str = './db/database.db') -> None:
    def __init__(self, limit:float, path: str = './results/database.db') -> None:
        engine = create_engine(f'sqlite:///{path}', echo=False)
        Base.metadata.create_all(engine)
        self.Session = sessionmaker()
        self.Session.configure(bind=engine)
        self.limit = limit

    def add_conclusion(self, ip: str, honeypot: int, not_honeypot: int):
        session = self.Session()
        entry = session.scalar(select(Conslusions).where(Conslusions.ip == ip))
        if entry == None:
            if honeypot/(honeypot + not_honeypot) >= self.limit:
                conclusion = ConclEnum.honeypot
            else:
                conclusion = ConclEnum.not_honeypot
                
            session.add(Conslusions(ip=ip, honeypot=honeypot,
                        not_honeypot=not_honeypot, conclusion=conclusion))
        else:
            entry.honeypot += honeypot
            entry.not_honeypot += not_honeypot
            if entry.honeypot / (entry.honeypot + entry.not_honeypot) >= self.limit:
                conclusion = ConclEnum.honeypot
            else:
                conclusion = ConclEnum.not_honeypot
            entry.conclusion = conclusion

        session.commit()
        session.close()

    def add_statistics(self, ip: str, ping_times: list, probabilities: list):
        session = self.Session()
        for ping_time, probability in zip(ping_times, probabilities):
            session.add(Statistics(ip = ip, ping_time= ping_time, probability = probability))
        session.commit()
        session.close()
        

