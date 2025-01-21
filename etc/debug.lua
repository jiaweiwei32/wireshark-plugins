-- DEBUG 环境变量等基础信息
local info = debug.getinfo(1) -- 获取当前函数的调试信息
for k, v in pairs(info) do
    print(k, v)
end

for modName, mod in pairs(package.loaded) do
    print("Loaded module:", modName)
end

print("Lua script search path:", package.path)
print("C module search path:", package.cpath)
