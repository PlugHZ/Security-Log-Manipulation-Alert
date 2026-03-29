require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config(); // บรรทัดนี้สำคัญมาก! เพื่อให้มันอ่านไฟล์ .env ได้

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.28", // ใช้เวอร์ชันตามที่พี่มีอยู่ได้เลย
  networks: {
    sepolia: {
      url: process.env.INFURA_URL,   // ดึงลิงก์สะพาน Alchemy จาก .env
      accounts: [process.env.PRIVATE_KEY] // ดึงกุญแจ MetaMask จาก .env
    }
  }
};