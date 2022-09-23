# Cleannie 小干净

## Designing Principle 设计理念
* 文本清理理论 (NOTION:20220923102029)

## Features 功能介绍
* 适用于一行一句型平白文本
* 替换自定义符号
* 去除行号
* 转换HTML字符实体为正常文字
* 替换非ASCII标点符号
* 删除多余空格
* 删除空行
* 空格分词
* 有注音符号的字母转无注音符号
* 统计不合法字符
* 统计字母-数字-符号组合占比
* 拆分标点符号连接的单词
* 清除单词两边的非发声符号
* 替换URL为[URL]
* 小写化

## Usage 用法
* 用例: corprep_en.pipeline(r'X:/test.txt', r'X:/')
	* 输入: 未经处理的平白文本
	* 输出: 处理后的平白文本和统计

## Dependencies 依赖
* BeautifulSoup
