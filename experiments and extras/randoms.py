# [0/3] [0/3] [300/500] = (0 * 3 + 0) * 500 + 300
# [0/3] [1/3] [300/500] = (0 * 3 + 1) * 500 + 300
# [2/3] [0/3] [300/500] = (2 * 3 + 0) * 500 + 300
# [2/3] [2/3] [300/500] = (2 * 3 + 2) * 500 + 300
# [current_cipher/cipher_list] [current_digest/digest_list] [current_pw/password_list]
# = (current_cipher * digest_list + current_digest) * password_list + current_pw

# char_count = 0
# printable_count = 0

# with open("test.txt", "r", encoding="ISO-8859-1") as f:
#     for line in f:
#         for char in line:
#             char_count += 1
#             if char.isalnum() or char.isascii():
#                 printable_count += 1

# print(printable_count, char_count)
# if printable_count >= (char_count / 10) * 9:  # At least 90% are printable characters
#     print(True)
# c = ["a", "b", "c", "e", "b", "a", "a", "d"]

# seen = set()
# seen_add = seen.add
# # c = [s for s in c if not (s in seen or seen_add(s))]

# seen_add("a")
# print(seen)
# print(seen_add("b"))
# print(seen)

# print(c)

# things = [" application/octet-stream; charset=binary\\n'", " application/x-dosexec; charset=binary\\n'", " application/zlib; charset=binary\\n'", " audio/x-mp4a-latm; charset=binary\\n'", ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/PCI8RKcNXzlVGeOP_rock\' (No such file or directory)\\n"', '                                                      cannot open `you\' (No such file or directory)\\n"', " application/gzip; charset=binary\\n'", ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/q8u9D9kxnV4p9iIf_i\' (No such file or directory)\\n"', '                                                  cannot open `love\' (No such file or directory)\\n"', '                                                   cannot open `you\' (No such file or directory)\\n"', " application/x-dvi; charset=binary\\n'", ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/JJ18DTuWuAqZXskF_te\' (No such file or directory)\\n"', '                                                    cannot open `amo\' (No such file or directory)\\n"', " inode/x-empty; charset=binary\\n'", ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/aVxlEIXezZXfbIFl_fuck\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/6IBHjByYqPgdJO4k_te\' (No such file or directory)\\n"', '                                                 cannot open `iubesc\' (No such file or directory)\\n"', " application/x-stargallery-thm; charset=binary\\n'", ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/OGNbhgLcP0pVIIFw_love\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/Ed4Qcfe56SZq1VrR_rock\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/W831TBRtrXBOewRz_i\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/lDG1jZg0nImSiGBA_te\' (No such file or directory)\\n"', " application/x-tex-tfm; charset=binary\\n'", ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/hvxV33inbzl1yJOW_fuck\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/qqyP4NxMP8pysBrA_te\' (No such file or directory)\\n"', " application/postscript; charset=binary\\n'", " application/x-cpio; charset=binary\\n'", " application/x-compress; charset=binary\\n'", ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/01URKFUVzJ8zaXwh_love\' (No such file or directory)\\n"', " text/PGP; charset=binary\\n'", ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/RQRY0qlHUhmvWyog_rock\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/twsvUk5U79jXlqbh_i\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/C7dOxuSAaOGTzafX_te\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/K1F3TKKwuYlLi5sK_fuck\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/w7BYblo9yJLoeBnS_te\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/8TiSEK0HoUmDXsUo_love\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/uwkCCnncw2IpYNPx_rock\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/dVYAEYeHTUUe9wDs_i\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/ynjwUtxZ7EXMLqMh_te\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/mApGZxMaqfnGu2gq_fuck\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/ParcOxwIT47kYb3X_te\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/gVa8nQuBwuR4ygDM_love\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/kO1l0MSYD9iH4Wyo_rock\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/POPUeq8kuk7gL39T_i\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/PUyc7tXMfC99GYDh_te\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/cBLM5uQAgalwe1B4_fuck\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/bPT1CTYIaAcsr47R_te\' (No such file or directory)\\n"', " image/jpeg; charset=binary\\n'", ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/V9z6BXEKqvhscFEm_love\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/NbmE5MBMfsg8MAEI_rock\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/kcyeXXeviWfoNfZb_i\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/SUnulyNQKQre7vLb_te\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/uNkFJJlnTUpiu7qd_fuck\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/4fNnVPhIUzAoctb1_te\' (No such file or directory)\\n"', ' cannot open `/root/crowbar_lab/hLvCpya9lxeMIbVt/g45sHihtJg8n9QzU_love\' (No such file or directory)\\n"']

# with open("thing.txt", "w") as f:
#     for thing in things:
#         f.write(thing)
#         f.write("\n")

# "abcde"
# a   = 0
# aa  = 5
# ba  = 10
# ca  = 15
# da  = 20
# ea  = 25
# aaa = 30
