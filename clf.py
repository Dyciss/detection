from numpy import array
from sklearn.gaussian_process import GaussianProcessClassifier
import pickle
import database


class Classifier:
    def __init__(self, limit: float, save_path: str = '') -> None:
        self.save_path = save_path
        self.db = database.database(limit=limit)
        self.limit = limit

    def load(self):
        with open(self.save_path, 'rb') as fd:
            self.clf = pickle.load(fd)

    def learn(self, stats: list, values: list, save_flag=False):
        stats = array(stats).reshape(-1, 1)
        self.clf = GaussianProcessClassifier()
        self.clf.fit(stats, values)
        if (save_flag):
            with open(self.save_path, 'wb') as fd:
                pickle.dump(self.clf, fd)

    def predict(self, host: str, input_data: list):
        data = array(input_data).reshape(-1, 1)
        values = self.clf.predict_proba(data)
        hp = 0
        no_hp = 0
        for elem in values:
            if elem[1] > self.limit:
                hp += 1
            else:
                no_hp += 1
        self.db.add_conclusion(ip=host, honeypot=hp, not_honeypot=no_hp)
        self.db.add_statistics(
            ip=host, ping_times=input_data, probabilities=[entry[1] for entry in values])
        return hp, no_hp, values