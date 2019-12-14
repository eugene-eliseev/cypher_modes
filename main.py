from Cryptodome.Cipher import DES
from Cryptodome import Random
from Cryptodome.Util.Padding import pad
from Cryptodome.Util import Counter


def to_str_b(b):
    # вывод инфы с разделением по блокам и выводом длины
    l = list(b)
    res = ""
    i = 0
    for d in l:
        symb = "{0:b}".format(d)
        i += len(symb)
        if i % 64 == 0:
            symb += ' | '
        while len(symb) < 8:
            symb = '0' + symb
            i += 1
            if i % 64 == 0:
                symb += ' | '
        res += symb
    return "{} [{}]".format(res, len(res) - 3 * (i // 64))


def show_diff(str1, str2):
    # вывод различий в двух строках
    diffs = 0
    for i in range(min(len(str1), len(str2))):
        if str1[i] != str2[i]:
            print('^', end='')
            diffs += 1
        else:
            print(' ', end='')
    print(" => {} различий".format(diffs), end='')
    diffs = abs(len(str1) - len(str2))
    if diffs > 0:
        print(" + разность длин:", diffs, end='')
    print()


def get_DES(key, mode):
    # возвращает класс DES
    if mode == DES.MODE_CTR:
        print("Create counter")
        counter = Counter.new(nbits=64)
        return DES.new(key, mode, counter=counter)
    return DES.new(key, mode)


def check_mode(mode, mode_str):
    print("############################  {}. {}  #################################".format(mode, mode_str))
    key = b"some key"
    message = "привет мир и так далее и тому подобное тут специально много текста чтобы блоков было больше"
    plaintext = pad(bytes(message, encoding='utf-8'), 8)

    iv = Random.new().read(DES.block_size)  # эта штука не используется, хотя можно. тут пусть останется для красоты

    print("Открытый текст")
    print(to_str_b(plaintext))

    msg = get_DES(key, mode).encrypt(plaintext)

    print("Закрытый текст")
    print(to_str_b(msg))

    msg_err = list(msg).copy()
    msg_err[24] = (msg_err[5] + 1) % 256  # делаем ошибку
    msg_err = bytes(msg_err)
    print("Закрытый текст с ошибкой")
    print(to_str_b(msg_err))
    show_diff(to_str_b(msg), to_str_b(msg_err))

    print("Расшифрованный текст")
    decr = get_DES(key, mode).decrypt(msg)
    print(to_str_b(decr))
    # print(decr.decode('utf-8')) # <- это вывод расшифрованного текста

    print("Расшифрованный текст с ошибкой")
    decr_err = get_DES(key, mode).decrypt(msg_err)
    print(to_str_b(decr_err))
    # print(decr_err.decode('utf-8')) # <- а тут лучше не выводить, это же код с ошибкой
    show_diff(to_str_b(decr), to_str_b(decr_err))
    print("##############################################################################")


check_mode(DES.MODE_OFB, "MODE_OFB")
check_mode(DES.MODE_CBC, "MODE_CBC")
check_mode(DES.MODE_CFB, "MODE_CFB")
check_mode(DES.MODE_CTR, "MODE_CTR")
check_mode(DES.MODE_ECB, "MODE_ECB")
check_mode(DES.MODE_EAX, "MODE_EAX")  # этот не нужен но пусть будет
