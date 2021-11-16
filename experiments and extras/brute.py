# Test different brute force algorithms created

from time import time

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
minimum_character = 1
maximum_character = 4

total = 0
for i in range(1, maximum_character + 1):
    total += len(charset) ** i
print(total)


# OLD BRUTE FUNCTION
def old_brute(password_index):  # 13.3 seconds
    for i in range(len(password_index)):
        if password_index[len(password_index) - i - 1] == ceiling:
            if i != len(password_index) - 1:
                password_index[len(password_index) - i - 1] = 0
                password_index[len(password_index) - i - 2] += 1
            else:
                password_index[0] = 0
                password_index.insert(0, 0)
    return "".join([charset[i] for i in password_index])


# NEW BRUTE FUNCTION
def dec_to_charset(n, chars=charset):  # 12.5 seconds
        if n < len(chars):
            return chars[n]
        else:
            return dec_to_charset(n // len(chars) - 1, chars) + chars[n % len(chars)]


# NEW BRUTE FUNCTION (NON-RECURSIVE VERSION)
def dec_to_charset2(n, chars=charset):  # 14.6 seconds
    string = ""
    if n < len(chars):
        return chars[n]
    while n >= 0:
        n, index = divmod(n, len(chars))
        n -= 1
        string = chars[index] + string
    return string


# OLD BRUTE
old_brute_times = []
for i in range(5):

    t = time()

    password_index = [0] * minimum_character  # Use to retrieve the associated characters in the charset
    ceiling = len(charset)
    while len(password_index) <= maximum_character:
        password = old_brute(password_index)
        password_index[-1] += 1

    old_brute_times.append(time() - t)
    print(f"Old brute: {i}")

# NEW BRUTE
new_brute_times = []
for i in range(5):

    t = time()

    password = ""
    password_dec = 0
    while len(password) <= maximum_character:
        password = dec_to_charset(password_dec)
        password_dec += 1

    new_brute_times.append(time() - t)
    print(f"New brute: {i}")

# NEW BRUTE NON-RECURSIVE
new2_brute_times = []
for i in range(5):

    t = time()

    password = ""
    password_dec = 0
    while len(password) <= maximum_character:
        password = dec_to_charset2(password_dec)
        password_dec += 1

    new2_brute_times.append(time() - t)
    print(f"New2 brute: {i}")


avg_old = sum(old_brute_times) / 5
avg_new = sum(new_brute_times) / 5
avg_new2 = sum(new2_brute_times) / 5
pwps_old = total / avg_old
pwps_new = total / avg_new
pwps_new2 = total / avg_new2
print(old_brute_times, avg_old)
print(new_brute_times, avg_new)
print(new2_brute_times, avg_new2)
print(round((pwps_new / pwps_old) * 100, 2))
print(round((pwps_new2 / pwps_old) * 100, 2))
print(round((pwps_new2 / pwps_new) * 100, 2))