import json


class Server:
    pass


class Client:
    pass


if __name__ == '__main__':
    with open("config.json") as fp:
        config = json.load(fp)
