import ping3
import nmap
import matplotlib.pyplot as plt
import clf
import pickle
from tcp_latency import measure_latency
from sklearn import metrics


def get_ping_data(host: str, count: int) -> list:
    stats = []
    summ = 0
    for _ in range(count):
        try:
            val = ping3.ping(host)
            summ += val
            stats.append(val)
        except:
            continue
    if stats == []:
        return None
    middle = summ/len(stats)
    tmp = 0
    for i in stats:
        tmp += (i - middle)**2
    disp = (tmp/len(stats))**0.5
    max_val = middle + disp
    min_val = middle - disp
    lst = []
    for i in stats:
        if i < max_val and i > min_val:
            lst.append(i)
    plt.figure(figsize=(16, 9))
    fig, ax = plt.subplots()
    fig.set_figwidth(16)
    fig.set_figheight(9)

    ax.hist(lst, bins=100, facecolor='g')
    ax.set_xlabel('Latency')
    ax.set_ylabel('Number of packets')
    ax.set_title(
        f'{host}: $\\mu={round(middle, 6):.6f},\\ \\sigma={round(disp, 6):.6f}$')
    ax.grid(True)
    plt.savefig(f'./results/pngs/ping/{host}.png')
    plt.close()
    return stats


def analize_network_ping(network: str, my_ip: str, classifier: clf.Classifier, count: int) -> list:
    scanner = nmap.PortScanner()
    scanner.scan(network, arguments='-sn')
    hosts = scanner.all_hosts()
    hosts.remove(my_ip)
    result_lst = []
    for host in hosts:
        result_lst.append({'host': host, 'results':  classifier.predict(
            host, input_data=get_ping_data(host=host, count=count))})
    return result_lst


def learn_clf_ping() -> clf.Classifier:
    with open('./learn_input/hp_stats/ping.stats', 'rb') as fd:
        stats = pickle.load(fd)
    values = [1 for _ in range(len(stats))]
    print(stats, values)
    with open('./learn_input/no_hp_stats/ping.stats', 'rb') as fd:
        stats += pickle.load(fd)

    values += [0 for _ in range(len(stats) - len(values))]
    classifier = clf.Classifier(
        limit=0.7, save_path='./results/ping_model.bin')
    classifier.learn(stats=stats, values=values, save_flag=True)
    return classifier


def get_tcp_data(host: str, port: int, count: int) -> list:
    stats = []
    summ = 0
    stats = measure_latency(host=host, port=port,
                            runs=count, human_output=False)

    middle = summ/len(stats)
    tmp = 0
    for i in stats:
        tmp += (i - middle)**2
    disp = (tmp/len(stats))**0.5
    max_val = middle + disp
    min_val = middle - disp
    lst = []
    for i in stats:
        if i < max_val and i > min_val:
            lst.append(i)
    plt.figure(figsize=(16, 9))
    fig, ax = plt.subplots()
    fig.set_figwidth(16)
    fig.set_figheight(9)

    ax.hist(lst, bins=100, facecolor='g')
    ax.set_xlabel('Latency')
    ax.set_ylabel('Number of packets')
    ax.set_title(
        f'{host}: $\\mu={round(middle, 6):.6f},\\ \\sigma={round(disp, 6):.6f}$')
    ax.grid(True)
    plt.savefig(f'./results/pngs/tcp/{host}.png')
    plt.close()
    return stats


def analize_network_tcp(network: str, my_ip: str, classifier: clf.Classifier, count: int) -> list:
    scanner = nmap.PortScanner()
    scanner.scan(network, '21-443', arguments='-sS')
    hosts = scanner.all_hosts()
    hosts.remove(my_ip)
    result_lst = []
    for host in hosts:
        try:
            ports = scanner[host]['tcp'].keys()
        except:
            continue
        for port in ports:
            tcp_data = get_tcp_data(host=host, port= port, count=count)
            if tcp_data == []:
                continue    
            result_lst.append({'host': host, 'port': port, 'results':  classifier.predict(
                host, input_data=tcp_data)})
    return result_lst


def learn_clf_tcp() -> clf.Classifier:
    with open('./learn_input/hp_stats/tcp.stats', 'rb') as fd:
        stats = pickle.load(fd)[1000:6000]
    values = [1 for _ in range(len(stats))]
    with open('./learn_input/no_hp_stats/tcp.stats', 'rb') as fd:
        stats += pickle.load(fd)[1000:6000]

    values += [0 for _ in range(len(stats) - len(values))]
    classifier = clf.Classifier(limit=0.7, save_path='./results/tcp_model.bin')
    classifier.learn(stats=stats, values=values, save_flag=True)
    return classifier


def draw_ROC(y_true: list, y_score : list, savepath: str) -> None:
    fpr, tpr, _ = metrics.roc_curve(y_true, y_score)
    plt.plot(fpr, tpr, label=f"AUC= {metrics.roc_auc_score(y_true, y_score)}")
    plt.legend()
    plt.title('ROC curve')
    plt.savefig(savepath)
    plt.close()


def draw_CM(y_true : list, predicted : list, savepath : str) -> None:
    disp = metrics.ConfusionMatrixDisplay.from_predictions(y_true, predicted)
    plt.title('Confusion Matrix')

    plt.savefig(savepath)
    plt.close()


def test(hp_ip: str, not_hp_ip : str, hp_port : int, not_hp_port: int, count : int) -> None:
    # ping_clf = clf.Classifier(limit=0.55, save_path='./results/ping_model.bin')
    # ping_clf.load()
    # tcp_clf = clf.Classifier(limit=0.55, save_path='./results/tcp_model.bin')
    # tcp_clf.load()

    ping_clf = learn_clf_ping()
    tcp_clf = learn_clf_tcp()

    true_labels = [1 for _ in range(500)]
    true_labels += [0 for _ in range(500)]

    _, _, prob_hp = ping_clf.predict(
        host=hp_ip, input_data=get_ping_data(hp_ip, count))
    _, _, prob_no_hp = ping_clf.predict(
        host=not_hp_ip, input_data=get_ping_data(not_hp_ip, count))
    prob_hp = [i[1] for i in prob_hp]
    prob_no_hp = [i[1] for i in prob_no_hp]
    prob = prob_hp + prob_no_hp
    print(prob)
    predicted_labels = [1 if i > 0.55 else 0 for i in prob]

    draw_ROC(y_true=true_labels, y_score=prob,
             savepath='./results/PING_ROC.png')
    draw_CM(y_true=true_labels, predicted=predicted_labels,
            savepath='./results/PING_CM.png')

    data_hp = get_tcp_data(hp_ip, hp_port, count)
    data_no_hp = get_tcp_data(not_hp_ip, not_hp_port, count)

    true_labels = [1 for _ in range(len(data_hp))]
    true_labels += [0 for _ in range(len(data_no_hp))]

    _, _, prob_hp = tcp_clf.predict(host=hp_ip, input_data=data_hp)
    _, _, prob_no_hp = tcp_clf.predict(
        host=not_hp_ip, input_data=data_no_hp)
    prob_hp = [i[1] for i in prob_hp]
    prob_no_hp = [i[1] for i in prob_no_hp]
    prob = prob_hp + prob_no_hp
    print(prob)
    predicted_labels = [1 if i > 0.55 else 0 for i in prob]

    draw_ROC(y_true=true_labels, y_score=prob,
             savepath='./results/TCP_ROC.png')
    draw_CM(y_true=true_labels, predicted=predicted_labels,
            savepath='./results/TCP_CM.png')

def analize_network(my_ip: str, network: str, count : int):
    # ping_clf = clf.Classifier(limit=0.55, save_path='./results/ping_model.bin')
    # ping_clf.load()
    # tcp_clf = clf.Classifier(limit=0.55, save_path='./results/tcp_model.bin')
    # tcp_clf.load()
    ping_clf = learn_clf_ping()
    tcp_clf = learn_clf_tcp()
    ping_results = analize_network_ping(network= network, my_ip= my_ip, classifier= ping_clf, count= count)

    for item in ping_results:
        host = item['host']
        if item['results'][0] > item['results'][1]:
            print(f'Host {host} is a honeypot (ping)')
        else:
            print(f'Host {host} is not a honeypot (ping)')

    tcp_results = analize_network_tcp(network= network, my_ip= my_ip, classifier= tcp_clf, count= count)

    for item in tcp_results:
        host = item['host']
        if item['results'][0] > item['results'][1]:
            print(f'Host {host} is a honeypot (tcp on port {item["port"]})')
        else:
            print(f'Host {host} is not a honeypot (tcp on port {item["port"]})')


if __name__ == '__main__':
    analize_network(network= '192.168.131.0/24', my_ip= '192.168.131.142', count= 10)