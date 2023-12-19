import os

def format_file(filename):
    formatted_lines = []
    with open(filename, 'r', encoding='utf-8') as file:
        lines = file.readlines()
        for line in lines:
            line = line.rstrip('\r\n')
            line = '"' + line.replace('"', '\\"') + '\\n" +'
            formatted_lines.append(line)

    # 删除文本尾部的空行
    while formatted_lines and not formatted_lines[-1].strip():
        formatted_lines.pop()

    # 替换最后一行的结尾
    if formatted_lines:
        formatted_lines[-1] = formatted_lines[-1].replace('\\n" +', '\\n";')

    # 添加前缀并写入新文件
    new_filename = f"format_{filename}"
    with open(new_filename, 'w', encoding='utf-8', newline='\n') as new_file:
        for line in formatted_lines:
            new_file.write(line + '\n')

# 处理 help1.txt 和 help2.txt
files_to_format = ['help1.txt', 'help2.txt']
for file in files_to_format:
    if os.path.exists(file):
        format_file(file)
        print(f"文件 {file} 格式化完成！")
    else:
        print(f"文件 {file} 不存在。")

