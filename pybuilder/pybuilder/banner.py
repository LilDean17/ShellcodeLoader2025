from pyfiglet import Figlet

def banner():
    # 生成大字和小字
    big_font = Figlet(font='doom', width=200)  # 加宽限制防止自动换行
    small_font = Figlet(font='small')           # 使用更紧凑的mini字体

    # 获取艺术字并分割成行列表
    big_text = big_font.renderText('Loader').rstrip('\n')
    big_lines = [line.rstrip() for line in big_text.split('\n')]
    big_width = max(len(line) for line in big_lines)
    big_height = len(big_lines)

    # 生成小号署名并分割成行列表
    small_text = small_font.renderText('by lil dean').rstrip('\n')
    small_lines = [line.rstrip() for line in small_text.split('\n')]
    small_width = max(len(line) for line in small_lines)
    small_height = len(small_lines)

    # 计算嵌入位置（右下角）
    vertical_pos = max(0, big_height - small_height)  # 垂直起始位置
    horizontal_pad = big_width - small_width - 2      # 水平右对齐留空（-2为留出间距）

    # 将小字嵌入到大字指定位置
    for i in range(small_height):
        if vertical_pos + i < big_height:
            target_line = vertical_pos + i
            # 拼接时保留原有字符 + 自动补空格 + 小字
            big_lines[target_line] = big_lines[target_line].ljust(big_width)
            big_lines[target_line] += ' ' * horizontal_pad + small_lines[i]

    # 输出最终效果
    print('\n'.join(big_lines))