#!/bin/bash

# 要检查的域名列表
domains=("gmail.com" "yahoo.com" "outlook.com")

# 定义颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # 无颜色

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

# 遍历所有域名进行检查
for domain in "${domains[@]}"; do
    check_mx_port_25 "$domain"
    echo
done