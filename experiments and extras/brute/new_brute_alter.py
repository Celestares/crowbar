"""
LAST TEST RESULT:
Iterations   : 15018570
All timings  : [15.275928211212158, 15.181932306289673, 15.557621479034424, 15.55373740196228, 15.48551812171936]
Average time : 15.440947504043579
Passwords/s  : 972705.310818572
"""

from time import time

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # Base 62 where a=0 and 9=61
minimum_character = 1
maximum_character = 4

total = 0
for i in range(1, maximum_character + 1):
    total += len(charset) ** i
print(f"Iterations required: {total}")    # Print total iterations required


def dec_to_charset2(n, chars=charset):
    string = ""
    if n < len(chars):                    # When the number is less than the base number
        return chars[n]
    while n >= 0:
        n, index = divmod(n, len(chars))  # divmod(n1, n2) outputs two values: n1 // n2, n1 % n2
        n -= 1
        string = chars[index] + string
    return string


new_brute_times = []
for i in range(5):

    t = time()

    password = ""
    password_dec = 0
    while len(password) <= maximum_character:
        password = dec_to_charset2(password_dec)
        password_dec += 1

    new_brute_times.append(time() - t)
    print(f"New brute: {i + 1}/5 tests done")


avg_new = sum(new_brute_times) / 5
pwps_new = total / avg_new
print(f"All timings  : {new_brute_times}")
print(f"Average time : {avg_new}")
print(f"Passwords/s  : {pwps_new}")
