from datetime import datetime


def str_to_date(s):
    return datetime.strptime(s, '%Y-%m-%d %H:%M:%S')
