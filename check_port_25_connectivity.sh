#!/bin/bash

# 要检查的域名列表
domains=("gmail.com" "yahoo.com" "outlook.com")

# 定义颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # 无颜色

# 检查必需的命令是否安装
check_requirements() {
    local missing_commands=()
    
    # 检查 dig 命令
    if ! command -v dig &> /dev/null; then
        missing_commands+=("dig (dnsutils 或 bind-utils)")
    fi
    
    # 检查 nc 命令
    if ! command -v nc &> /dev/null; then
        missing_commands+=("nc (netcat)")
    fi
    
    # 如果有缺失的命令，显示安装建议
    if [ ${#missing_commands[@]} -ne 0 ]; then
        echo -e "${RED}错误: 以下命令未安装:${NC}"
        for cmd in "${missing_commands[@]}"; do
            echo "  - $cmd"
        done
        echo -e "\n请使用包管理器安装缺失的包:"
        echo "Ubuntu/Debian: sudo apt install dnsutils netcat"
        echo "CentOS/RHEL: sudo yum install bind-utils nc"
        exit 1
    fi
}

# 检查每个域名的MX服务器是否能连接到25端口
check_mx_port_25() {
    local domain=$1
    echo -e "Checking MX records for domain: $domain"
    
    # 查询MX记录
    mx_records=$(dig +short MX "$domain" | awk '{print $2}')

    if [[ -z "$mx_records" ]]; then
        echo -e "${RED}No MX records found for $domain${NC}"
        return
    fi

    for mx in $mx_records; do
        echo -e "Checking MX server $mx on port 25..."
        
        # 尝试连接MX服务器的25端口
        nc -z -w 5 "$mx" 25
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}Success: Able to connect to $mx on port 25.${NC}"
        else
            echo -e "${RED}Failed: Unable to connect to $mx on port 25.${NC}"
        fi
    done
}

# 在主程序开始前调用检查
check_requirements

# 遍历所有域名进行检查
for domain in "${domains[@]}"; do
    check_mx_port_25 "$domain"
    echo
done