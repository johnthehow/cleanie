# 程序思路见corprep总体规划_20211024171633.drawio
# 附件: 欧洲语言特殊字母表_20211022170741.zip
# 用例: cleannie.pipeline(r'X:/test.txt', r'X:/')
# 		输入: 未经处理的平白文本
# 		输出: 处理后的平白文本和统计
import re
import string
import pickle
from pathlib import Path
import warnings
import bs4
warnings.filterwarnings("ignore")

BASIC_LATIN_LOWER = 'abcdefghijklmnopqrstuvwxyz'
BASIC_LATIN_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
BASIC_LATIN_ABC = BASIC_LATIN_LOWER + BASIC_LATIN_UPPER
LATIN_SUP = 'ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõöøùúûüýþÿ'
LATIN_EXT_A = 'ĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕĖėĘęĚěĜĝĞğĠġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁłŃńŅņŇňŊŋŌōŎŏŐőŒœŔŕŖŗŘřŚśŜŝŞşŠšŢţŤťŦŧŨũŪūŬŭŮůŰűŲųŴŵŶŷŸŹźŻżŽžſ'
LATIN_ABC = BASIC_LATIN_ABC + LATIN_SUP + LATIN_EXT_A

EN_SPECIAL_ABC_LOWER = ''
EN_SPECIAL_ABC_UPPER = ''
LANG = 'EN'
PRINT_TITLE = 'PIPELINE_EN'
EN_SPECIAL_ABC = EN_SPECIAL_ABC_LOWER + EN_SPECIAL_ABC_UPPER
END_PUNCT = '[.!?]'

LEGAL_ABC = LATIN_ABC + LATIN_SUP +LATIN_EXT_A + EN_SPECIAL_ABC + DIACRITICS
LEGAL_DIGIT = '0123456789'
VOCAL_CHAR = LEGAL_ABC + LEGAL_DIGIT
LEGAL_PUNCT = string.punctuation + '°' + '$£€¥₹'
LEGAL_CHAR = LEGAL_ABC + LEGAL_PUNCT + LEGAL_DIGIT

CUSTOM_REPLACE = dict()
with open('custom_replace.txt',mode='r',encoding='utf-8') as file:
	cr_lines = file.readlines()
	cr_lines = [i[:-1] for i in cr_lines] #去除末尾的换行符\n
	cr_lines = [i.split(sep='\t') for i in cr_lines]
	for i in cr_lines:
		CUSTOM_REPLACE[i[0]] = i[1]



# 在整个文本中替换乱码
def replace_gibberish_doc(doc):
	hex_map = CUSTOM_REPLACE
	hex_map_keys = list(hex_map.keys()) 
	for key in hex_map_keys:
		doc = doc.replace(key,hex_map[key])
	return doc

# 在每句话中替换乱码
def replace_gibberish_strlines(strlines):
	proc_lines = []
	hex_map = CUSTOM_REPLACE
	hex_map_keys = list(hex_map.keys()) 
	for line in strlines:
		for key in hex_map_keys:
			line = line.replace(key,hex_map[key])
		proc_lines.append(line)
	return proc_lines


# 删除多余空格和非空格间隔符为空格, 必须在分行前使用
def remove_extra_space(strlines):
	proc_lines = []
	for line in strlines:
		proc_line = re.sub(' {2,}',' ',line)
		proc_lines.append(proc_line)
	return proc_lines


# 记录不合法的token: 即含有未定义在合法字符中的字符的token
def log_illegal_token(tklines):
	rec = []
	for line in tklines:
		for token in line:
			illegal_cnt = 0
			for char in token:
				if char not in LEGAL_CHAR:
					illegal_cnt += 1
			if illegal_cnt != 0:
				rec.append(token)
	res = '\n'.join(rec)
	return res


# 替换html字符实体, 必须在分行后使用, 分行前使用会丢失部分换行符
def replace_html_char_entity(strlines):
	proc_lines = []
	for line in strlines:
		proc_lines.append(bs4.BeautifulSoup(line).text)
	return proc_lines


# 分行后使用, 删除空行
def remove_empty_strlines(strlines):
	res = []
	empty_line_cnt = 0
	for line in strlines:
		if len(line) != 0:
			res.append(line)
		else:
			empty_line_cnt += 1
	return res


# 所有清理完成后, 删除空行
def remove_empty_tklines(tklines):
	res = []
	empty_line_cnt = 0
	for line in tklines:
		if len(line) != 0:
			res.append(line)
		else:
			empty_line_cnt += 1
	print(f'{PRINT_TITLE}: {empty_line_cnt} Empty Lines Removed')
	return res

# 判断一个token是否含有非法字符
def is_contain_illegal_char(token):
	res = False
	for char in token:
		if char not in LEGAL_CHAR:
			res = True
	return res

# 判断一个token是否含有且只含有字母
def is_only_legalabc(token):
	match_cnt = 0
	for char in token:
		if char in LEGAL_ABC:
			match_cnt += 1
	if match_cnt == len(token) and len(token) != 0:
		res = True
	else:
		res = False
	return res


def is_only_numeric(token):
	match_cnt = 0
	for char in token:
		if char in LEGAL_DIGIT:
			match_cnt += 1
	if match_cnt == len(token) and len(token) != 0:
		res = True
	else:
		res = False
	return res


# 判断一个token是否 含有且只含有非发声字符
def is_only_nonvocal(token):
	match_cnt = 0
	for char in token:
		if char not in LEGAL_ABC and char not in LEGAL_DIGIT:
			match_cnt += 1
	if match_cnt == len(token) and len(token) != 0:
		res = True
	else:
		res = False
	return res


# 判断token是否为单质字符串, 依赖函数is_only_en_abc(), is_only_nonvocal()
def is_homo(token):
	return is_only_legalabc(token) or is_only_numeric(token) or is_only_nonvocal(token)  and len(token) != 0


# 判断token是否 是且仅是 字母+符号 的混合
def is_mix_legalabc_nonvocal(token):
	abc_cnt = 0
	nonvocal_cnt = 0
	for char in token:
		if char in LEGAL_ABC:
			abc_cnt += 1
		elif char not in VOCAL_CHAR:
			nonvocal_cnt += 1
	if abc_cnt + nonvocal_cnt == len(token) and abc_cnt*nonvocal_cnt and len(token) != 0:
		res = True
	else:
		res = False
	return res


# 判断一个token是否是 字母和数字的混合
def is_mix_legalabc_num(token):
	abc_cnt = 0
	num_cnt = 0
	for char in token:
		if char in LEGAL_ABC:
			abc_cnt += 1
		elif char in LEGAL_DIGIT:
			num_cnt += 1
	if abc_cnt + num_cnt == len(token) and abc_cnt*num_cnt and len(token) !=0 :
		res = True
	else:
		res = False
	return res

# 判断一个token是否是且仅是数字和符号的混合
def is_mix_num_nonvocal(token):
	num_cnt = 0
	nonvocal_cnt = 0
	for char in token:
		if char in LEGAL_DIGIT:
			num_cnt += 1
		elif char not in LEGAL_ABC:
			nonvocal_cnt += 1
	if num_cnt + nonvocal_cnt == len(token) and num_cnt*nonvocal_cnt and len(token) !=0:
		res = True
	else:
		res = False
	return res


# 判断一个token是否是且仅是 数字-符号-字母 的混合
def is_mix_legalabc_num_nonvocal(token):
	res = False
	if is_homo(token) == False:
		if is_mix_legalabc_num(token) == False:
			if is_mix_legalabc_nonvocal(token) == False:
				if is_mix_num_nonvocal(token) == False:
					if len(token) != 0:
						res = True
	return res


# 判断一个token是否含有且仅含有一段连续的字母串
def is_contain_onlyone_legalabc_seq(token):
	char_cnt = 0
	abc_cnt = 0
	abc_idxs = []
	for char in token:
		char_cnt += 1
		if char in LEGAL_ABC:
			abc_cnt += 1
			abc_idxs.append(char_cnt)
	res = all(a+1==b for a, b in zip(abc_idxs, abc_idxs[1:])) and abc_cnt !=0
	return res

# 含有且仅含有一段连续的字母串的token中所有的字母并粘合为一个token
# 依赖 is_contain_onlyone_legalabc_seq
def keep_only_legalabc_seq(token):
	if is_contain_onlyone_legalabc_seq(token):
		proc_token = ''
		for char in token:
			if char in LEGAL_ABC:
				proc_token += char
	else:
		print('keep_only_legalabc_seq: contain more than one continuous abc sequence')
	return proc_token


# 判断是否有形如state-of-the-art, vis-a-vis形式的单词
def is_contain_sota(token):
	regex = re.compile(f'[{LEGAL_ABC}]+(-[{LEGAL_ABC}]+)+')
	if re.search(regex,token) != None:
		res = True
	else:
		res = False
	return res

def keep_only_sota(token):
	if is_contain_sota(token):
		regex = re.compile(f'[{LEGAL_ABC}]+(-[{LEGAL_ABC}]+)+')
		match = re.search(regex,token)
		res = match.group()
	else:
		print('keep_only_sota: trying to extract sota while don\'t have one')
	return res

# 判断是否是 u.s.a. 或 u.s.a 或 a.m. 或 p.m形式
def is_usa(token):
	regex = re.compile(f'^[{LEGAL_ABC}](\.[{LEGAL_ABC}])+\.?$')
	if re.search(regex,token) != None:
		res = True
	else:
		res = False
	return res

# 判断是否是 ^单词,单词$ 形式的token
def is_abc_comma_abc(token):
	regex = re.compile(f'^([{LEGAL_ABC}]{{2,}})(,)([{LEGAL_ABC}]{{2,}})$')
	if re.search(regex,token) != None:
		res = True
	else:
		res = False
	return res


# 拆分逗号分隔的单词
def split_abc_comma_abc(token):
	if is_abc_comma_abc(token):
		res = []
		regex = re.compile(f'^([{LEGAL_ABC}]{{2,}})(,)([{LEGAL_ABC}]{{2,}})$')
		match = re.search(regex,token)
		res.append(match.group(1))
		res.append(match.group(3))
	else:
		print('split_abc_comma_abc: trying to split abc,abc while is not one')
	return res

# 判断是否是.!?分隔的单词
def is_abc_endpunct_abc(token):
	regex = re.compile(f'^([{LEGAL_ABC}]{{2,}})({END_PUNCT})([{LEGAL_ABC}]{{2,}})$')
	if re.search(regex,token) != None:
		res = True
	else:
		res = False
	return res

# 拆分.!?分隔的单词
def split_abc_endpunct_abc(token):
	if is_abc_endpunct_abc(token):
		res = []
		regex = re.compile(f'^([{LEGAL_ABC}]{{2,}})({END_PUNCT})([{LEGAL_ABC}]{{2,}})$')
		match = re.search(regex,token)
		res.append(match.group(1))
		res.append(match.group(3))
	else:
		print('split_abc_endpunct_abc: trying to split abc.!?abc while is not one')
	return res

# 是否包含'号缩约式
def is_contain_contract(token):
	res = False
	regex = re.compile(f'[{LEGAL_ABC}]+\'[{LEGAL_ABC}]+')
	if re.search(regex,token) != None:
		if len(re.findall('\'',token)) == 1:
			res = True
	return res

# 依赖 is_contain_contract
def keep_only_contract(token):
	regex = re.compile(f'[{LEGAL_ABC}]+\'[{LEGAL_ABC}]+')
	if is_contain_contract(token) == True:
		match = re.search(regex,token).group()
	return match

# 清除token两端的非发声符号
def strip_nonvocal_mix_nonvocal(token):
	origin = token
	if token[0] not in VOCAL_CHAR:
		token = token[1:]
	else:
		pass
	if token[-1] not in VOCAL_CHAR:
		token = token[:-1]
	else:
		pass
	if token == origin:
		pass
	else:
		token = strip_nonvocal_mix_nonvocal(token)
	return token

# 依赖: 无依赖函数
# 各种引号大全见https://unicode-table.com/en/sets/quotation-marks/
def replace_nonascii_punct(strlines):
	#前边: 错误的符号 后边: 正确的符号
	nonvocal_conv_table = [('“”„‟⹂❞❝〞〝〟«»❠🙷🙶🙸＂「」⸗	','"'),('‹›’‘‛❛❜❟′ʻʾ´`ʼʿ̕ʽ՝̒̔︐´＇᠈̒','\''),('‒—–―‑‐ー−─¬―—–‐－‑-﹣⁃᠆‧⹀⸚゠֊͜','-'),('…⋯᠁','...'),('⸴̦،🄊⹁⍪⹌⸲‚꛵𖺗𝪇🄁',','),('⁄∕̷⼃','/')]
	proc_lines = []
	for line in strlines:
		proc_line = ''
		for char in line:
			proc_char = char
			for pair in nonvocal_conv_table:
				if char in pair[0]:
					proc_char = pair[1]
				else:
					pass
			proc_line += proc_char
		proc_lines.append(proc_line)
	return proc_lines

# 判断是否含有URL
def is_contain_url(token):
	url = '\.com|\.net|\.org|\.edu|\.gov|\.mil|\.aero|\.asia|\.biz|\.cat|\.coop|\.info|\.int|\.jobs|\.mobi|\.museum|\.name|\.post|\.pro|\.tel|\.travel|\.xxx|\.ac|\.ad|\.ae|\.af|\.ag|\.ai|\.al|\.am|\.an|\.ao|\.aq|\.ar|\.as|\.at|\.au|\.aw|\.ax|\.az|\.ba|\.bb|\.bd|\.be|\.bf|\.bg|\.bh|\.bi|\.bj|\.bm|\.bn|\.bo|\.br|\.bs|\.bt|\.bv|\.bw|\.by|\.bz|\.ca|\.cc|\.cd|\.cf|\.cg|\.ch|\.ci|\.ck|\.cl|\.cm|\.cn|\.co|\.cr|\.cs|\.cu|\.cv|\.cx|\.cy|\.cz|\.dd|\.de|\.dj|\.dk|\.dm|\.do|\.dz|\.ec|\.ee|\.eg|\.eh|\.er|\.es|\.et|\.eu|\.fi|\.fj|\.fk|\.fm|\.fo|\.fr|\.ga|\.gb|\.gd|\.ge|\.gf|\.gg|\.gh|\.gi|\.gl|\.gm|\.gn|\.gp|\.gq|\.gr|\.gs|\.gt|\.gu|\.gw|\.gy|\.hk|\.hm|\.hn|\.hr|\.ht|\.hu|\.id|\.ie|\.il|\.im|\.in|\.io|\.iq|\.ir|\.is|\.it|\.je|\.jm|\.jo|\.jp|\.ke|\.kg|\.kh|\.ki|\.km|\.kn|\.kp|\.kr|\.kw|\.ky|\.kz|\.la|\.lb|\.lc|\.li|\.lk|\.lr|\.ls|\.lt|\.lu|\.lv|\.ly|\.ma|\.mc|\.md|\.me|\.mg|\.mh|\.mk|\.ml|\.mm|\.mn|\.mo|\.mp|\.mq|\.mr|\.ms|\.mt|\.mu|\.mv|\.mw|\.mx|\.my|\.mz|\.na|\.nc|\.ne|\.nf|\.ng|\.ni|\.nl|\.no|\.np|\.nr|\.nu|\.nz|\.om|\.pa|\.pe|\.pf|\.pg|\.ph|\.pk|\.pl|\.pm|\.pn|\.pr|\.ps|\.pt|\.pw|\.py|\.qa|\.re|\.ro|\.rs|\.ru|\.rw|\.sa|\.sb|\.sc|\.sd|\.se|\.sg|\.sh|\.si|\.sj|\. Ja|\.sk|\.sl|\.sm|\.sn|\.so|\.sr|\.ss|\.st|\.su|\.sv|\.sx|\.sy|\.sz|\.tc|\.td|\.tf|\.tg|\.th|\.tj|\.tk|\.tl|\.tm|\.tn|\.to|\.tp|\.tr|\.tt|\.tv|\.tw|\.tz|\.ua|\.ug|\.uk|\.us|\.uy|\.uz|\.va|\.vc|\.ve|\.vg|\.vi|\.vn|\.vu|\.wf|\.ws|\.ye|\.yt|\.yu|\.za|\.zm|\.zw|\.php|\.html|\.htm|\.asp|http|https|ftp|www|://'
	if re.search(url,token) != None:
		res = True
	else:
		res = False
	return res

# 是否含有货币符号
def is_contain_currency(token):
	regex = re.compile('[$£€¥₹](\d+)?(,)?(\d+)?(\.?)(\d)+')
	if re.search(regex,token) != None:
		res = True
	else:
		res = False
	return res

def keep_only_currency(token):
	regex = re.compile('[$£€¥₹](\d+)?(,)?(\d+)?(\.?)(\d)+')
	match = re.search(regex,token)
	res = match.group()
	return res

# 替换URL为[URL]
def replace_url(token):
	if is_contain_url(token):
		res = '[URL]'
	return res

def lower_token(tklines):
	proc_lines = []
	sent_cnt = 0
	for line in tklines:
		sent_cnt += 1
		proc_line = []
		for token in line:
			proc_line.append(token.lower())
		proc_lines.append(proc_line)
	return proc_lines

# 载入lepzig语料库(sentences), 处理成初步的tokenized_lines
# 设计流程图见 corprep_pipeline总体规划_20211024171633.drawio
# 包含总体规划中的 文档层 和 句子层
def load_lepzig(filename):
	# 文件层: 打开文件
	print(f'{PRINT_TITLE}>>>load_lepzig: Loading Lepzig sentences...')
	with open(filename,mode='r',encoding='utf-8') as lpzfile:
		doc = lpzfile.read()
	print(f'{PRINT_TITLE}>>>load_lepzig: Document length: {len(doc)} chars')

	# 文档层: 替换乱码
	print(f'{PRINT_TITLE}>>>load_lepzig: Replacing gibberish in whole doc, 1st time...')
	doc = replace_gibberish_doc(doc)
	print(f'{PRINT_TITLE}>>>load_lepzig: Replacing gibberish in whole doc, 2nd time...')
	doc = replace_gibberish_doc(doc)
	print(f'{PRINT_TITLE}>>>load_lepzig: Replacing gibberish in whole doc, 3rd time...')
	doc = replace_gibberish_doc(doc)
	print(f'{PRINT_TITLE}>>>load_lepzig: Document length after gibberish replaced: {len(doc)} chars')

	# 文档层: 分行
	print(f'{PRINT_TITLE}>>>load_lepzig: Splitting lines...')
	strlines = doc.split(sep='\n')
	
	# 文档层: 删除分行造成的最后一行空行
	strlines = strlines[:-1]
	print(f'{PRINT_TITLE}>>>load_lepzig: Total strlines {len(strlines)} lines')

	# 句子层: 去除行号
	print(f'{PRINT_TITLE}>>>load_lepzig: Revmoing line numbers...')
	strlines = [re.sub('^\d+\t','',line) for line in strlines]

	# 句子层: 替换HTML字符实体
	print(f'{PRINT_TITLE}>>>load_lepzig: Replacing html entities...')
	strlines = replace_html_char_entity(strlines)
	print(f'{PRINT_TITLE}>>>load_lepzig: Total lines after HTML replaced: {len(strlines)} lines')

	# 句子层: 替换乱码
	print(f'{PRINT_TITLE}>>>load_lepzig: Replacing gibberish after HTML replaced, 1st time...')
	strlines = replace_gibberish_strlines(strlines)
	print(f'{PRINT_TITLE}>>>load_lepzig: Replacing gibberish after HTML replaced, 2nd time...')
	strlines = replace_gibberish_strlines(strlines)
	print(f'{PRINT_TITLE}>>>load_lepzig: Replacing gibberish after HTML replaced, 3rd time...')
	strlines = replace_gibberish_strlines(strlines)
	print(f'{PRINT_TITLE}>>>load_lepzig: Document length after gibberish replaced: {len(" ".join(strlines))} chars')

	# 句子层: 替换非ASCII标点符号
	print(f'{PRINT_TITLE}>>>load_lepzig: replace_nonascii_punct...')
	strlines = replace_nonascii_punct(strlines)

	# 句子层: 查找拆分多合一行
	# print(f'{PRINT_TITLE}>>>load_lepzig: Splitting duplex strlines...')
	# strlines = split_duplex_lines(strlines)
	# print(f'{PRINT_TITLE}>>>load_lepzig: Total strlines after splitting: {len(strlines)} ...')
	
	# 句子层: 删除多余空格
	print(f'{PRINT_TITLE}>>>load_lepzig: Removing extra spaces...')
	strlines = remove_extra_space(strlines)
	
	# 句子层: 删除空行
	print(f'{PRINT_TITLE}>>>load_lepzig: Removing empty strlines...')
	strlines = remove_empty_strlines(strlines)
	print(f'{PRINT_TITLE}>>>load_lepzig: Total Lines after Empty Lines Removed {len(strlines)}')

	# 句子层: 空格分词
	tklines = [line.split() for line in strlines]
	return tklines

# 设计流程图见 corprep_sanitize流程图_20211018151342.drawio
# 上级设计流程图见 corprep_pipeline总体规划_20211024171633.drawio
# 包含总体规划中的token层
def sanitize_token(tklines):
	proc_lines = []
	for line in tklines:
		proc_line = []
		for token in line:
			# 长度为0: 是
			if len(token) == 0:
				pass
			# 长度为0: 否
			else:
				# 包含非法字符: 是 -> 不入列
				if is_contain_illegal_char(token) == True:
					pass
				# 包含非法字符: 否
				else:
					# 纯粹token: 是
					if is_homo(token) == True:
						if is_only_legalabc(token) == True:
							proc_line.append(token)
						elif is_only_numeric(token) == True:
							proc_line.append(token)
						elif is_only_nonvocal(token) == True:
							continue
					# 纯粹token: 否
					else:
						# 字母 + 符号混合: 是
						if is_mix_legalabc_nonvocal(token) == True:
							if is_contain_onlyone_legalabc_seq(token) == True:
								proc_line.append(keep_only_legalabc_seq(token))
							elif is_contain_sota(token):
								proc_line.append(keep_only_sota(token))
							elif is_usa(token):
								proc_line.append(strip_nonvocal_mix_nonvocal(token))
							elif is_abc_comma_abc(token):
								proc_line += split_abc_comma_abc(token)
							elif is_contain_url(token):
								proc_line.append(replace_url(token))
							elif is_abc_endpunct_abc(token):
								proc_line += split_abc_endpunct_abc(token)
							elif is_contain_contract(token):
								proc_line.append(keep_only_contract(token))
							else:
								proc_line.append(strip_nonvocal_mix_nonvocal(token))
						# 字母 + 数字混合: 是
						elif is_mix_legalabc_num(token):
							proc_line.append(token)
						# 数字 + 符号混合: 是
						elif is_mix_num_nonvocal(token):
							if is_contain_currency(token):
								proc_line.append(keep_only_currency(token))
							else:
								proc_line.append(strip_nonvocal_mix_nonvocal(token))
						# 字母 + 数字 + 符号混合: 是
						elif is_mix_legalabc_num_nonvocal(token):
							# URL: 是
							if is_contain_url(token):
								proc_line.append(replace_url(token))
							# 包括且一段且仅一段连续字母: 是
							elif is_contain_onlyone_legalabc_seq(token) == True:
								proc_line.append(keep_only_legalabc_seq(token))
							# 非URL 也不包括且一段且仅一段连续字母
							else:
								proc_line.append(strip_nonvocal_mix_nonvocal(token))
						else:
							print(f'impossible token {token} detected, logical problem in sanitizer.')
		proc_lines.append(proc_line)
	return proc_lines

def stats(tklines):
	stat_log = []
	token_cnt = 0
	num_token_cnt = 0
	abc_token_cnt = 0
	abc_num_token_cnt = 0
	abc_nonvocal_token_cnt = 0
	num_nonvocal_token_cnt = 0
	abc_num_nonvocal_token_cnt = 0
	for line in tklines:
		for token in line:
			token_cnt += 1
			if is_only_legalabc(token) == True:
				abc_token_cnt += 1
			elif is_only_numeric(token) == True:
				num_token_cnt += 1
			elif is_mix_legalabc_num(token) == True:
				abc_num_token_cnt += 1
			elif is_mix_legalabc_nonvocal(token) == True:
				abc_nonvocal_token_cnt += 1
			elif is_mix_num_nonvocal(token) == True:
				num_nonvocal_token_cnt += 1
			else:
				abc_num_nonvocal_token_cnt += 1
	print(f'Stats: Total Tokens: \t{token_cnt}')
	stat_log.append(f'Stats: Total Tokens: \t{token_cnt}')
	print(f'Stats: Total Illegal Tokens: \t{len(illegal_tokens)}')
	stat_log.append(f'Stats: Total Illegal Tokens: \t{len(illegal_tokens)}')
	print(f'Stats: Total Lines after Processing: \t{len(tklines)}')
	stat_log.append(f'Stats: Total Lines after Processing: \t{len(tklines)}')
	print(f'Stats: Abc Tokens: \t{abc_token_cnt}({100*abc_token_cnt/token_cnt:.3f}%)')
	stat_log.append(f'Stats: Abc Tokens: \t{abc_token_cnt}({100*abc_token_cnt/token_cnt:.3f}%)')
	print(f'Stats: Abc + Num Tokens: \t{abc_num_token_cnt}({100*abc_num_token_cnt/token_cnt:.3f}%)')
	stat_log.append(f'Stats: Abc + Num Tokens: \t{abc_num_token_cnt}({100*abc_num_token_cnt/token_cnt:.3f}%)')
	print(f'Stats: Abc + Sym Tokens: \t{abc_nonvocal_token_cnt}({100*abc_nonvocal_token_cnt/token_cnt:.3f}%)')
	stat_log.append(f'Stats: Abc + Sym Tokens: \t{abc_nonvocal_token_cnt}({100*abc_nonvocal_token_cnt/token_cnt:.3f}%)')
	print(f'Stats: Abc + Num + Sym Tokens: \t{abc_num_nonvocal_token_cnt}({100*abc_num_nonvocal_token_cnt/token_cnt:.3f}%)')
	stat_log.append(f'Stats: Abc + Num + Sym Tokens: \t{abc_num_nonvocal_token_cnt}({100*abc_num_nonvocal_token_cnt/token_cnt:.3f}%)')
	print(f'Stats: Num Tokens: \t{num_token_cnt}({100*num_token_cnt/token_cnt:.3f}%)')
	stat_log.append(f'Stats: Num Tokens: \t{num_token_cnt}({100*num_token_cnt/token_cnt:.3f}%)')
	print(f'Stats: Num + Sym Tokens: \t{num_nonvocal_token_cnt}({100*num_nonvocal_token_cnt/token_cnt:.3f}%)')
	stat_log.append(f'Stats: Num + Sym Tokens: \t{num_nonvocal_token_cnt}({100*num_nonvocal_token_cnt/token_cnt:.3f}%)')
	return stat_log

# 设计图见corprep_pipeline总体规划_20211024171633.drawio
def pipeline(filename,savepath):
	filenamepobj = Path(filename)
	savepathpobj = Path(savepath)
	lepzig_sents_filename = filenamepobj.name
	print(f'{PRINT_TITLE}: Processing file {filenamepobj.stem}')
	print(f"====================PROCESS({LANG})====================")
	# 句子层
	print(f'{PRINT_TITLE}: load_lepzig...')
	proc_lines = load_lepzig(filename)
	# token层
	print(f'{PRINT_TITLE}: log_illegal_token...')
	global illegal_tokens
	illegal_tokens = log_illegal_token(proc_lines)
	print(f'{PRINT_TITLE}: sanitize_token...')
	proc_lines = sanitize_token(proc_lines)
	print(f'{PRINT_TITLE}: lower_token...')
	proc_lines = lower_token(proc_lines)
	# 收尾层
	print(f'{PRINT_TITLE}: remove_empty_tklines')
	proc_lines = remove_empty_tklines(proc_lines)
	print(f"====================SUMMARY({LANG})====================")
	stat = stats(proc_lines)
	print(f"====================SAVING({LANG})====================")
	try:
		with open(f'{savepathpobj.joinpath(filenamepobj.stem)}.pkl',mode='wb') as save_pkl:
			pickle.dump(proc_lines,save_pkl)
			print(f'{PRINT_TITLE}: Result pickle saved at: {savepathpobj.joinpath(filenamepobj.stem)}.pkl')
	except:
		print('Failed saving result pickle file.')
	try:
		with open(f'{savepathpobj.joinpath(filenamepobj.stem)}_except.txt',mode='w',encoding='utf-8') as save_except:
			save_except.write(illegal_tokens)
			print(f'{PRINT_TITLE}: Illegal tokens saved at: {savepathpobj.joinpath(filenamepobj.stem)}.txt')
	except:
		with open(f'{savepathpobj.joinpath(filenamepobj.stem)}_except.pkl',mode='wb') as save_except_fail_pkl:
			pickle.dump(illegal_tokens,save_except_fail_pkl)
		print(f'Failed saving illegal tokens. PKL saved instead at {savepathpobj.joinpath(filenamepobj.stem)}_except.pkl')
	try:
		with open(f'{savepathpobj.joinpath(filenamepobj.stem)}_stats.txt',mode='w',encoding='utf-8') as save_stats:
			for i in stat:
				save_stats.write(i)
				save_stats.write('\n')
			print(f'{PRINT_TITLE}: Statistics saved at: {savepathpobj.joinpath(filenamepobj.stem)}.txt')
	except:
		print(f'Failed saving statistics.')
	try:
		with open(f'{savepathpobj.joinpath(filenamepobj.stem)}_pdoc.txt',mode='w',encoding='utf-8') as save_pdoc:
			for tkline in proc_lines:
				save_pdoc.write(' '.join(tkline))
				save_pdoc.write('\n')
			print(f'{PRINT_TITLE}: Processed docs saved at: {savepathpobj.joinpath(filenamepobj.stem)}.txt')
	except:

		print(f'Failed saving processed docs.')
	return proc_lines