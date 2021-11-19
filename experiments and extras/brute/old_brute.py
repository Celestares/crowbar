"""
LAST TEST RESULT:
Iterations   : 15018570
All timings  : [14.606029510498047, 14.560389280319214, 14.525494575500488, 14.536494016647339, 14.573764324188232]
Average time : 14.560434341430664
Passwords/s  : 1031464.4225458127
"""

from time import time

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # Base 62 where a=0 and 9=61
minimum_character = 1
maximum_character = 4

total = 0
for i in range(1, maximum_character + 1):
    total += len(charset) ** i
print(f"Iterations required: {total}")  # Print total iterations required


def old_brute(password_index):
    for i in range(len(password_index)):                            # Iterate through all "digits"
        if password_index[len(password_index) - i - 1] == ceiling:  # If a digit exceed the radix (base number)
            if i != len(password_index) - 1:                        # Check if its not the left-most digit
                password_index[len(password_index) - i - 1] = 0     # Make the current digit back to 0
                password_index[len(password_index) - i - 2] += 1    # Incremenet digit to the left by 1 (e.g. 09 --> 10)
            else:
                password_index[0] = 0                               # Make the current digit back to 0
                password_index.insert(0, 0)                         # Add a new digit at the start (e.g. 999 --> 0000)
    return "".join([charset[i] for i in password_index])            # Map digits to its charset value (e.g. 0=a, 1=b, 61=9)


old_brute_times = []
for i in range(5):

    t = time()

    password_index = [0] * minimum_character         # The start number in a form of list containing each digits
    ceiling = len(charset)                           # Ceiling is the base number (62)
    while len(password_index) <= maximum_character:
        password = old_brute(password_index)
        password_index[-1] += 1                      # Increment "ones" digit by 1

    old_brute_times.append(time() - t)
    print(f"Old brute: {i + 1}/5 tests done")


avg_old = sum(old_brute_times) / 5
pwps_old = total / avg_old
print(f"All timings  : {old_brute_times}")
print(f"Average time : {avg_old}")
print(f"Passwords/s  : {pwps_old}")
