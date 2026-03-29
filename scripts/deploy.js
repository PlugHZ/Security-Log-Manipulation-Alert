const hre = require("hardhat");

async function main() {
  // ดึง Smart Contract ที่เราชื่อ LogStorage มาเตรียมไว้
  const LogStorage = await hre.ethers.getContractFactory("LogStorage");
  
  console.log(" กำลังติดตั้ง Smart Contract ลงบน Blockchain...");
  const contract = await LogStorage.deploy();

  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log(` ติดตั้งสำเร็จ! Contract Address คือ: ${address}`);
  console.log("--------------------------------------------------");
  console.log(" ก๊อปปี้เลข Address ด้านบนไปใส่ในไฟล์ recordLog ของคุณ");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});