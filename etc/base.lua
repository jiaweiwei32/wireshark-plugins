local M = {}

-- 将字节流（十六进制字节）转换为二进制字符串
function M.byte_to_binary(byte)
    local binary = ""
    -- 对每个字节进行转换
    for i = 7, 0, -1 do
        binary = binary .. (bit.band(byte, 2^i) > 0 and "1" or "0")
    end
    return binary
end

-- 将十六进制字符串转换为二进制
function M.hex_to_binary(hex)
    -- 去除开头的 "0x"（如果有的话）
    if hex:sub(1, 2) == "0x" then
        hex = hex:sub(3)
    end

    -- 转换十六进制字符串为十进制数
    local decimal_value = tonumber(hex, 16)
    
    -- 自定义函数：将十进制数转换为二进制
    local binary_str = ""
    while decimal_value > 0 do
        local remainder = decimal_value % 2
        binary_str = remainder .. binary_str
        decimal_value = math.floor(decimal_value / 2)
    end

    -- 如果二进制字符串为空，说明是 0，直接返回 "00000000"
    if binary_str == "" then
        binary_str = "00000000"
    end

    -- 如果需要保证8位，不足时补零
    while #binary_str < 8 do
        binary_str = "0" .. binary_str
    end

    return binary_str
end

-- 定义函数，将十六进制字符串转换为十进制整数
function M.hex_to_decimal(hex_str)
    -- 去除字符串中的前导0（可选）
    hex_str = hex_str:gsub("^0+", "")
    
    -- 如果字符串为空，则认为它是0
    if hex_str == "" then
        return 0
    end

    -- 使用 tonumber 函数将十六进制字符串转换为十进制
    local decimal_value = tonumber(hex_str, 16)
    
    -- 如果输入无效，返回错误提示
    if not decimal_value then
        error("Invalid hex string: " .. hex_str)
    end
    
    return decimal_value
end


function M.get_Date()
    -- 获取当前时间
    local current_time = os.date("*t")  -- 返回一个表，包含年、月、日、时、分、秒等字段

    -- 获取当前秒数的小数部分（即毫秒）
    local milliseconds = math.floor((os.clock() * 1000) % 1000)

    -- 构造时间字符串
    local formatted_time = string.format("%04d-%02d-%02d %02d:%02d:%02d.%03d", 
                                        current_time.year, current_time.month, current_time.day, 
                                        current_time.hour, current_time.min, current_time.sec, 
                                        milliseconds)

    -- 打印结果
    return formatted_time

end

return M
