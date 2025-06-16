const { ethers } = require('ethers');
const http = require('http');
const url = require('url');
require('dotenv').config();

// 配置
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';

// 从环境变量读取私钥
const PRIVATE_KEY = process.env.PRIVATE_KEY;

if (!PRIVATE_KEY) {
    console.error('❌ 错误: 请在环境变量中设置 PRIVATE_KEY');
    console.error('💡 提示: 创建 .env 文件并添加 PRIVATE_KEY=0x你的私钥');
    process.exit(1);
}

/**
 * 清理和修复EIP-712类型定义
 */
function cleanEIP712Types(types, primaryType) {
    const cleanedTypes = { ...types };
    
    // 移除EIP712Domain，ethers.js会自动处理
    if (cleanedTypes.EIP712Domain) {
        console.log("⚠️  移除types中的EIP712Domain，ethers.js会自动处理");
        delete cleanedTypes.EIP712Domain;
    }
    
    // 确保primaryType存在于types中
    if (primaryType && !cleanedTypes[primaryType]) {
        throw new Error(`primaryType "${primaryType}" 在types中不存在`);
    }
    
    console.log("✅ 清理后的types:", JSON.stringify(cleanedTypes, null, 2));
    return cleanedTypes;
}

/**
 * 通用EIP-712签名函数
 */
async function signEIP712Universal(privateKey, domain, types, message, primaryType = null) {
    try {
        console.log("🔐 开始EIP-712签名...");
        console.log("📝 原始types:", JSON.stringify(types, null, 2));
        
        // 创建钱包实例
        const wallet = new ethers.Wallet(privateKey);
        console.log("📍 签名地址:", wallet.address);
        
        // 清理types（移除EIP712Domain等）
        const cleanedTypes = cleanEIP712Types(types, primaryType);
        
        // 如果没有指定primaryType，尝试推断
        if (!primaryType && Object.keys(cleanedTypes).length > 0) {
            // 找到第一个类型作为primaryType
            for (const typeName of Object.keys(cleanedTypes)) {
                if (cleanedTypes[typeName] && cleanedTypes[typeName].length > 0) {
                    primaryType = typeName;
                    console.log(`🎯 推断primaryType为: ${primaryType}`);
                    break;
                }
            }
        }
        
        if (!primaryType) {
            throw new Error("无法确定primaryType，请在请求中指定");
        }
        
        console.log("🎯 使用primaryType:", primaryType);
        console.log("🏗️  domain:", JSON.stringify(domain, null, 2));
        console.log("🏗️  types:", JSON.stringify(cleanedTypes, null, 2));
        console.log("📄 message:", JSON.stringify(message, null, 2));
        
        // 进行签名
        const signature = await wallet._signTypedData(domain, cleanedTypes, message);
        
        // 分解签名
        const splitSig = ethers.utils.splitSignature(signature);
        
        // 验证签名
        const recoveredAddress = ethers.utils.verifyTypedData(domain, cleanedTypes, message, signature);
        
        const result = {
            success: true,
            signature: signature,
            signerAddress: wallet.address,
            recoveredAddress: recoveredAddress,
            isValid: recoveredAddress.toLowerCase() === wallet.address.toLowerCase(),
            primaryType: primaryType,
            signatureBreakdown: {
                r: splitSig.r,
                s: splitSig.s,
                v: splitSig.v,
                recoveryParam: splitSig.recoveryParam
            },
            signedData: {
                domain: domain,
                types: cleanedTypes,
                primaryType: primaryType,
                message: message
            },
            timestamp: new Date().toISOString()
        };
        
        console.log("✅ 签名成功!");
        console.log("🔒 签名结果:", signature);
        
        return result;
        
    } catch (error) {
        console.error("❌ 签名失败:", error.message);
        return {
            success: false,
            error: error.message,
            signature: null,
            timestamp: new Date().toISOString()
        };
    }
}

/**
 * 处理CORS跨域
 */
function setCORSHeaders(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
}

/**
 * 解析POST请求体
 */
function parsePostData(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            try {
                resolve(JSON.parse(body));
            } catch (error) {
                reject(error);
            }
        });
        req.on('error', reject);
    });
}

/**
 * API路由处理
 */
async function handleRequest(req, res) {
    const parsedUrl = url.parse(req.url, true);
    const path = parsedUrl.pathname;
    const method = req.method;
    
    console.log(`📡 ${method} ${path} - ${new Date().toISOString()}`);
    
    // 设置CORS头
    setCORSHeaders(res);
    
    // 处理OPTIONS预检请求
    if (method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }
    
    try {
        if (path === '/api/sign' && method === 'POST') {
            // EIP-712签名接口
            const requestData = await parsePostData(req);
            console.log("📥 收到签名请求");
            
            // 验证请求数据
            if (!requestData.domain || !requestData.types || !requestData.message) {
                res.writeHead(400);
                res.end(JSON.stringify({
                    success: false,
                    error: "请求必须包含domain, types, message字段"
                }));
                return;
            }
            
            // 执行签名
            const result = await signEIP712Universal(
                PRIVATE_KEY, 
                requestData.domain, 
                requestData.types, 
                requestData.message,
                requestData.primaryType
            );
            
            res.writeHead(200);
            res.end(JSON.stringify(result, null, 2));
            
        } else if (path === '/api/health' && method === 'GET') {
            // 健康检查接口
            res.writeHead(200);
            res.end(JSON.stringify({
                status: 'ok',
                service: 'EIP-712 签名服务',
                timestamp: new Date().toISOString(),
                version: '1.0.0'
            }));
            
        } else if (path === '/api/address' && method === 'GET') {
            // 获取签名地址接口
            const wallet = new ethers.Wallet(PRIVATE_KEY);
            res.writeHead(200);
            res.end(JSON.stringify({
                address: wallet.address,
                timestamp: new Date().toISOString()
            }));
            
        } else {
            // 404 Not Found
            res.writeHead(404);
            res.end(JSON.stringify({
                success: false,
                error: `路径 ${path} 不存在`,
                availableEndpoints: [
                    'POST /api/sign - EIP-712签名',
                    'GET /api/health - 健康检查',
                    'GET /api/address - 获取签名地址'
                ]
            }));
        }
        
    } catch (error) {
        console.error("❌ 服务器错误:", error);
        res.writeHead(500);
        res.end(JSON.stringify({
            success: false,
            error: "服务器内部错误"
        }));
    }
}

/**
 * 创建HTTP服务器
 */
const server = http.createServer(handleRequest);

// 启动服务器
server.listen(PORT, HOST, () => {
    console.log('🚀 EIP-712 签名服务器已启动!');
    console.log(`📍 服务地址: http://${HOST}:${PORT}`);
    console.log(`🔗 API接口:`);
    console.log(`   POST http://${HOST}:${PORT}/api/sign - EIP-712签名`);
    console.log(`   GET  http://${HOST}:${PORT}/api/health - 健康检查`);
    console.log(`   GET  http://${HOST}:${PORT}/api/address - 获取签名地址`);
    console.log('🛑 按 Ctrl+C 停止服务器');
    
    // 显示签名地址（不显示私钥）
    const wallet = new ethers.Wallet(PRIVATE_KEY);
    console.log(`🔑 签名地址: ${wallet.address}`);
});

// 优雅关闭
process.on('SIGINT', () => {
    console.log('\n🛑 正在关闭服务器...');
    server.close(() => {
        console.log('✅ 服务器已关闭');
        process.exit(0);
    });
});

// 错误处理
server.on('error', (error) => {
    console.error('❌ 服务器错误:', error);
    if (error.code === 'EADDRINUSE') {
        console.error(`端口 ${PORT} 已被占用，请更换端口或关闭占用程序`);
    }
});

module.exports = { signEIP712Universal }; 