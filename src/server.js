
require("dotenv").config();

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient, Prisma } = require("@prisma/client");

const app = express();
const prisma = new PrismaClient();

app.use(express.json());

// ========================================
// 1. KIỂM TRA SERVER
// ========================================
app.get("/", (req, res) => {
  res.json({
    message: "Monolithic E-commerce API is running",
  });
});

// ========================================
// 2. ĐĂNG KÝ TÀI KHOẢN
// ========================================
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, fullname, password } = req.body;

    if (
      typeof username !== "string" ||
      !username.trim() ||
      typeof fullname !== "string" ||
      !fullname.trim() ||
      typeof password !== "string" ||
      password.length < 6
    ) {
      return res.status(400).json({
        message: "Vui lòng nhập username, fullname và mật khẩu từ 6 ký tự",
      });
    }

    const existingUser = await prisma.user.findUnique({
      where: { username: username.trim() },
    });

    if (existingUser) {
      return res.status(409).json({
        message: "Tên đăng nhập đã tồn tại",
      });
    }

    let role = await prisma.role.findUnique({
      where: { rolename: "normal" },
    });

    if (!role) {
      role = await prisma.role.create({
        data: { rolename: "normal" },
      });
    }

    let membership = await prisma.membership.findUnique({
      where: { mname: "normal" },
    });

    if (!membership) {
      membership = await prisma.membership.create({
        data: {
          mname: "normal",
          score: 10,
        },
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        username: username.trim(),
        fullname: fullname.trim(),
        password: hashedPassword,
        roleid: role.roleid,
        mid: membership.mid,
      },
    });

    return res.status(201).json({
      message: "Đăng ký thành công",
      user: {
        uid: user.uid,
        username: user.username,
        fullname: user.fullname,
        role: role.rolename,
        membership: membership.mname,
        score: membership.score,
      },
    });
  } catch (error) {
    console.error("Lỗi đăng ký:", error);

    return res.status(500).json({
      message: "Lỗi máy chủ khi đăng ký",
    });
  }
});

// ========================================
// 3. ĐĂNG NHẬP VÀ CẤP JWT TOKEN
// ========================================
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      !username ||
      !password
    ) {
      return res.status(400).json({
        message: "Vui lòng nhập username và password",
      });
    }

    const user = await prisma.user.findUnique({
      where: { username },
      include: {
        role: true,
        membership: true,
      },
    });

    if (!user) {
      return res.status(401).json({
        message: "Tên đăng nhập hoặc mật khẩu không đúng",
      });
    }

    const passwordValid = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordValid) {
      return res.status(401).json({
        message: "Tên đăng nhập hoặc mật khẩu không đúng",
      });
    }

    if (!process.env.JWT_SECRET) {
      throw new Error("Chưa cấu hình JWT_SECRET trong file .env");
    }

    const token = jwt.sign(
      {
        uid: user.uid,
        username: user.username,
        role: user.role.rolename,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || "1d",
      }
    );

    return res.json({
      message: "Đăng nhập thành công",
      token,
      user: {
        uid: user.uid,
        username: user.username,
        fullname: user.fullname,
        role: user.role.rolename,
        membership: user.membership.mname,
        score: user.membership.score,
      },
    });
  } catch (error) {
    console.error("Lỗi đăng nhập:", error);

    return res.status(500).json({
      message: "Lỗi máy chủ khi đăng nhập",
    });
  }
});

// ========================================
// 4. MIDDLEWARE XÁC THỰC JWT
// ========================================
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Vui lòng đăng nhập để thực hiện chức năng này",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    if (!process.env.JWT_SECRET) {
      throw new Error("Chưa cấu hình JWT_SECRET");
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      message: "Token không hợp lệ hoặc đã hết hạn",
    });
  }
}

// ========================================
// 5. THÊM SẢN PHẨM
// ========================================
app.post("/api/products", async (req, res) => {
  try {
    const { pname, price, quantity } = req.body;

    if (
      typeof pname !== "string" ||
      !pname.trim() ||
      price === undefined ||
      quantity === undefined ||
      !Number.isFinite(Number(price)) ||
      !Number.isInteger(Number(quantity)) ||
      Number(price) <= 0 ||
      Number(quantity) < 0
    ) {
      return res.status(400).json({
        message:
          "Tên sản phẩm, giá lớn hơn 0 và số lượng nguyên không âm là bắt buộc",
      });
    }

    const product = await prisma.product.create({
      data: {
        pname: pname.trim(),
        price: Number(price),
        quantity: Number(quantity),
      },
    });

    return res.status(201).json({
      message: "Thêm sản phẩm thành công",
      product,
    });
  } catch (error) {
    console.error("Lỗi thêm sản phẩm:", error);

    return res.status(500).json({
      message: "Lỗi máy chủ khi thêm sản phẩm",
    });
  }
});

// ========================================
// 6. LẤY DANH SÁCH SẢN PHẨM
// ========================================
app.get("/api/products", async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      orderBy: { pid: "asc" },
    });

    return res.json(products);
  } catch (error) {
    console.error("Lỗi lấy sản phẩm:", error);

    return res.status(500).json({
      message: "Lỗi máy chủ khi lấy sản phẩm",
    });
  }
});

// ========================================
// 7. ĐẶT HÀNG - YÊU CẦU JWT
// ========================================
app.post("/api/orders", authenticateToken, async (req, res) => {
  try {
    const { items } = req.body;

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({
        message: "Đơn hàng phải có ít nhất một sản phẩm",
      });
    }

    // Kiểm tra dữ liệu và gộp các sản phẩm trùng pid
    const quantities = new Map();

    for (const item of items) {
      const pid = Number(item.pid);
      const qty = Number(item.qty);

      if (
        !Number.isInteger(pid) ||
        pid <= 0 ||
        !Number.isInteger(qty) ||
        qty <= 0
      ) {
        return res.status(400).json({
          message: "Mỗi sản phẩm phải có pid và qty là số nguyên dương",
        });
      }

      quantities.set(pid, (quantities.get(pid) || 0) + qty);
    }

    const order = await prisma.$transaction(
      async (tx) => {
        const orderItems = [];

        // Kiểm tra tồn kho và giá của từng sản phẩm
        for (const [pid, qty] of quantities) {
          const product = await tx.product.findUnique({
            where: { pid },
          });

          if (!product) {
            const error = new Error(`Không tìm thấy sản phẩm pid=${pid}`);
            error.statusCode = 404;
            throw error;
          }

          if (product.quantity < qty) {
            const error = new Error(
              `Sản phẩm ${product.pname} không đủ tồn kho. Còn ${product.quantity}, yêu cầu ${qty}`
            );
            error.statusCode = 400;
            throw error;
          }

          orderItems.push({
            pid,
            qty,
            unit_price: product.price,
          });
        }

        // Tạo đơn hàng của người đang đăng nhập
        const newOrder = await tx.order.create({
          data: {
            uid: req.user.uid,
          },
        });

        // Tạo chi tiết đơn hàng
        await tx.orderDetail.createMany({
          data: orderItems.map((item) => ({
            oid: newOrder.oid,
            pid: item.pid,
            qty: item.qty,
            unit_price: item.unit_price,
          })),
        });

        // Trừ tồn kho có điều kiện để tránh bán vượt số lượng
        for (const item of orderItems) {
          const result = await tx.product.updateMany({
            where: {
              pid: item.pid,
              quantity: { gte: item.qty },
            },
            data: {
              quantity: { decrement: item.qty },
            },
          });

          if (result.count !== 1) {
            const error = new Error(
              `Tồn kho sản phẩm pid=${item.pid} vừa thay đổi. Vui lòng thử lại`
            );
            error.statusCode = 409;
            throw error;
          }
        }

        // Tạo thông tin giao hàng
        await tx.shipment.create({
          data: {
            oid: newOrder.oid,
            status: "Pending",
          },
        });

        // Trả về đơn hàng kèm chi tiết và giao hàng
        return tx.order.findUnique({
          where: { oid: newOrder.oid },
          include: {
            details: {
              include: {
                product: true,
              },
            },
            shipments: true,
          },
        });
      }
    );

    return res.status(201).json({
      message: "Đặt hàng thành công",
      order,
    });
  } catch (error) {
    console.error("Lỗi đặt hàng:", error);

    return res.status(error.statusCode || 500).json({
      message: error.message || "Lỗi máy chủ khi đặt hàng",
    });
  }
});

// ========================================
// 8. XEM ĐƠN HÀNG CỦA TÀI KHOẢN
// ========================================
app.get("/api/orders", authenticateToken, async (req, res) => {
  try {
    const orders = await prisma.order.findMany({
      where: {
        uid: req.user.uid,
      },
      include: {
        details: {
          include: {
            product: true,
          },
        },
        shipments: true,
      },
      orderBy: {
        oid: "desc",
      },
    });

    return res.json(orders);
  } catch (error) {
    console.error("Lỗi lấy đơn hàng:", error);

    return res.status(500).json({
      message: "Lỗi máy chủ khi lấy đơn hàng",
    });
  }
});

// ========================================
// 9. KHỞI ĐỘNG SERVER
// ========================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
