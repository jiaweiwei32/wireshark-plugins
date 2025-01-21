print("Lua V1 加载")
package.path = package.path .. ";/Users/gavin/.local/lib/wireshark/etc/?.lua"
package.cpath = package.cpath .. ";/Users/gavin/.local/lib/wireshark/etc/?.so"

local base = require("base")

local tcp_ports = {8084,8284}
-- 定义协议
local tcp_proto = Proto("Dubbo2", "Apache Dubbo Protocol")

-- 定义协议字段
local fMagic = ProtoField.uint16("dubbo.magic", "Magic", base.HEX)
local Length = ProtoField.uint32("dubbo.length", "TCP Length", base.DEC)
local fDubboLength = ProtoField.uint32("dubbo.dubboLength", "DubboLength", base.DEC)
local ReqFlag = ProtoField.string("dubbo.isRequest", "IsRequest", base.UNICODE)
local f2Way = ProtoField.bool("dubbo.isTwoWay", "IsTwoWay", base.NONE)
local fEvent = ProtoField.bool("dubbo.event", "IsEvent", base.NONE)
local fSerializationID = ProtoField.uint8("dubbo.serializationID", "SerializationID", base.DEC)
local fStatus = ProtoField.string("dubbo.status", "Status", base.UNICODE)
local fRequestID = ProtoField.uint32("dubbo.requestID", "RequestID", base.DEC)
local fDubboVersion = ProtoField.string("dubbo.dubboVersion", "DubboVersion", base.UNICODE)
local fServiceName = ProtoField.string("dubbo.serviceName", "ServiceName", base.UNICODE)
local fServiceVersion = ProtoField.string("dubbo.version", "Version", base.UNICODE)
local fMethodName = ProtoField.string("dubbo.methodName", "MethodName", base.UNICODE)
local fMethodParamTypes = ProtoField.string("dubbo.methodParamTypes", "MethodParamTypes", base.UNICODE)
local fMethodArgs = ProtoField.string("dubbo.methodArgs", "MethodArguments", base.UNICODE)
local fAttachments = ProtoField.string("dubbo.attachments", "Attachments", base.UNICODE)

-- 在协议中添加字段
tcp_proto.fields = { 
    fMagic, Length, fDubboLength, ReqFlag, f2Way, fEvent, 
    fSerializationID, fStatus, fRequestID, 
    fDubboVersion, fServiceName, fServiceVersion, fMethodName,
    fMethodParamTypes
}

function tcp_proto.dissector(buffer, pinfo, tree)
    -- 获取原有的 "data" dissector，用于显示 Transmission Control Protocol 的数据
    local data_dis = Dissector.get("data")

    -- 判断是否为Dubbo Magic
    local magic = buffer(0, 2)  -- 获取前2个字节作为魔术字节
    if magic:uint() == 0xdabb then
        -- 设置协议列名称
        pinfo.cols.protocol = tcp_proto.name

        -- 创建协议树并在其中添加字段
        local subtree = tree:add(tcp_proto, buffer(), "Dubbo Protocol Data")

        local magic_offset = 0
        local magic_length = 2
        local magic = buffer(magic_offset, magic_length)
        -- local magic = base.bytes_to_string(magic_byte)
        -- local magic_value = magic_bytes:uint()
        -- local magic = string.format("0x%04x", magic_value)
        -- 显示魔术字节
        subtree:add(fMagic, magic) 

        -- 获取数据包的总长度
        local length = buffer:len()
        -- 显示包长度
        subtree:add(Length, length)

        local DubboLength_offset = 12
        local DubboLength_length = 4
        local DubboLength_bytes = buffer(DubboLength_offset, DubboLength_length)
        local DubboLength_hex = tostring(DubboLength_bytes)
        local DubboLength = base.hex_to_decimal(DubboLength_hex)
        subtree:add(fDubboLength, DubboLength)

        local byte_c2 = buffer(2, 1)
        local byte_c2_hex = string.format("0x%02x", byte_c2:uint())
        local byte_value =  base.byte_to_binary(byte_c2_hex)
        local result = {}
        -- 对字符串逐位解析
        for i = 1, #byte_value do
            local bit = byte_value:sub(i, i)  -- 提取当前位的值
            if i == 1 then
                -- 第一位决定 Req/Res
                result.req_res = (bit == "1") and "Req" or "Resp"
            elseif i == 2 then
                -- 第二位决定 2Way
                result.twoway = (bit == "1") and 1 or 0
            elseif i == 3 then
                -- 第三位决定 Event
                result.event = (bit == "1") and 1 or 0
            elseif i >= 4 and i <= 8 then
                -- 剩下的位表示 Serialization ID
                result.serialization_id = result.serialization_id or ""
                result.serialization_id = result.serialization_id .. bit
            end
        end
        -- 将 Serialization ID 转换为十进制
        result.serialization_id = tonumber(result.serialization_id, 2)
        IsRequest = result.req_res
        subtree:add(ReqFlag, IsRequest)
        IsTwoWay = result.twoway
        subtree:add(f2Way, IsTwoWay)
        IsEvent = result.event
        subtree:add(fEvent, IsEvent)
        subtree:add(fSerializationID, result.serialization_id)


        local RequestID_offset = 4
        local RequestID_length = 8
        local RequestID_bytes = buffer(RequestID_offset, RequestID_length)
        local RequestID_hex = tostring(RequestID_bytes)
        local RequestID = base.hex_to_decimal(RequestID_hex)   
        subtree:add(fRequestID, RequestID)    


        if IsRequest == "Req" then
            local offset = 16
            local DubboVersion_byte = buffer(offset,1)
            local DubboVersion_hex = tostring(DubboVersion_byte)
            local DubboVersion_Length = base.hex_to_decimal(DubboVersion_hex)
            offset = offset + 1
            local Dubboversion_byte = buffer(offset,DubboVersion_Length)
            local dubboVersion = Dubboversion_byte:string()
            subtree:add(fDubboVersion, dubboVersion)

            offset = offset + 1 + DubboVersion_Length
            local ServiceName_len_byte = buffer(offset,1)
            local ServiceName_len_hex = tostring(ServiceName_len_byte)
            local ServiceName_Length = base.hex_to_decimal(ServiceName_len_hex)
            offset = offset + 1
            local ServiceName_byte = buffer(offset,ServiceName_Length)
            local ServiceName = ServiceName_byte:string()
            subtree:add(fServiceName, ServiceName)

            offset = offset + ServiceName_Length
            local ServiceVersion_len_byte = buffer(offset,1)
            local ServiceVersion_len_hex = tostring(ServiceVersion_len_byte)
            local ServiceVersion_Length = base.hex_to_decimal(ServiceVersion_len_hex)
            offset = offset + 1
            local ServiceVersion_byte = buffer(offset,ServiceVersion_Length)
            local ServiceVersion = ServiceVersion_byte:string()
            subtree:add(fServiceVersion, ServiceVersion) 

            offset = offset + ServiceVersion_Length
            local MethodName_len_byte = buffer(offset,1)
            local MethodName_len_hex = tostring(MethodName_len_byte)
            local MethodName_Length = base.hex_to_decimal(MethodName_len_hex)
            offset = offset + 1
            local MethodName_byte = buffer(offset,MethodName_Length)
            local MethodName = MethodName_byte:string()
            subtree:add(fMethodName, MethodName)    


            offset = offset + MethodName_Length
            local MethodParamTypes_len_byte = buffer(offset,1)
            local MethodParamTypes_len_hex = tostring(MethodParamTypes_len_byte)
            local MethodParamTypes_Length = base.hex_to_decimal(MethodParamTypes_len_hex)
            offset = offset + 1
            local MethodParamTypes_byte = buffer(offset,MethodParamTypes_Length)
            local MethodParamTypes = MethodParamTypes_byte:string()
            subtree:add(fMethodParamTypes, MethodParamTypes)                  

            print("【DEBUG信息】\n当前时间:" .. base.get_Date() .. "\nMagic:".. magic .. "\nTCP Length:" .. 
                length .. " byte" .. "\nDubboLength:" .. DubboLength .. "\nIsRequest:" .. IsRequest .. 
                "\nIsTwoWay:" .. IsTwoWay .. "\nIsEvent:" .. IsEvent .. "\nSerializationID:" .. result.serialization_id .. 
                "\nRequestID:" .. RequestID .. " byte" .. "\ndubboVersion" .. dubboVersion .. "\nServiceName:" .. 
                ServiceName .. "\nServiceVersion: " .. ServiceVersion .. "\nMethodName:" .. MethodName .. 
                "\nMethodParamTypes:" ..  MethodParamTypes,"数据类型:",type(MethodParamTypes))
            print("\nMagic:" .. magic .. "\t 数据类型:" .. type(magic))
        else
            offset = 3 
            status_length = 1 
            local status_byte = buffer(offset,status_length)
            local status_hex = tostring(status_byte)
            local status_code = base.hex_to_decimal(status_hex)
            local status_dic = {}
            if status_code == 20 then
                status_dic.status = "OK"
            elseif status_code == 30 then
                status_dic.status = "CLIENT_TIMEOUT"
            elseif status_code == 31 then
                status_dic.status = "SERVER_TIMEOUT" 
            elseif status_code == 40 then
                status_dic.status = "BAD_REQUEST"
            elseif status_code == 50 then
                status_dic.status = "BAD_RESPONSE"
            elseif status_code == 60 then
                status_dic.status = "SERVICE_NOT_FOUND"
            elseif status_code == 70 then
                status_dic.status = "SERVICE_ERROR"
            elseif status_code == 80 then
                status_dic.status = "SERVER_ERROR"
            elseif status_code == 90 then
                status_dic.status = "CLIENT_ERROR"
            elseif status_code == 100 then
                status_dic.status = "SERVER_THREADPOOL_EXHAUSTED_ERROR"
            else
                status_dic.status = "UNKONW CODE:" .. status_code
            end
            status = status_dic.status
            subtree:add(fStatus, status)    
                                
            print("statsu_byte:" .. status .. "\t 数据类型:" .. type(status))
        end

        -- 调用原始的 "data" dissector，显示原始的传输数据
        local data_subtree = subtree:add("Raw Data", buffer)
        data_dis:call(buffer, pinfo, data_subtree)
    else
        -- 如果不是Dubbo Magic，则调用原有的 "data" dissector，显示原始数据
        data_dis:call(buffer, pinfo, tree)
    end
end

-- 获取 TCP 端口号表并注册协议到指定端口
local tcp_table = DissectorTable.get("tcp.port")
for _, port in ipairs(tcp_ports) do
    tcp_table:add(port, tcp_proto)
end

