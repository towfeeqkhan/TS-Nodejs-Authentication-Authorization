import { Request, Response } from "express";
import {
  forgotPasswordSchema,
  loginSchema,
  registerSchema,
  resetPasswordSchema,
} from "./auth.schema";
import { User } from "../../models/user.model";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";
import { generateToken } from "../../lib/token";
import ms from "ms";
import crypto from "crypto";

export async function registerHandler(req: Request, res: Response) {
  try {
    const validation = registerSchema.safeParse(req.body);

    if (!validation.success) {
      return res.status(400).json({
        message: "Invalid data",
        errors: validation.error.flatten(),
      });
    }

    const { name, email, password } = validation.data;

    const existingUser = await User.findOne({ email: email });

    if (existingUser) {
      return res.status(409).json({
        message:
          "Email Id already exist, please try again with a different email id",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const newUser = await User.create({
      email,
      passwordHash,
      name,
    });

    // email verification

    const verifyToken = jwt.sign(
      { _id: newUser._id },
      process.env.JWT_EMAIL_VERIFICATION_SECRET!,
      { expiresIn: "1d" },
    );

    const verifyUrl = `${process.env.APP_URL}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newUser.email,
      "Verify your email",
      `
      <p>Please verify your email by clicking the link below</p>
      <a href=${verifyUrl}>${verifyUrl}</a>
      `,
    );

    return res.status(201).json({
      message: "User registered",
      user: {
        _id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
      },
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.query.token as string;

  if (!token) {
    return res.status(400).json({
      message: "Verification token is missing",
    });
  }

  try {
    const payload = jwt.verify(
      token,
      process.env.JWT_EMAIL_VERIFICATION_SECRET!,
    ) as {
      _id: string;
    };

    const user = await User.findById(payload._id);

    if (!user) {
      return res.status(401).json({
        message: "User not found",
      });
    }

    if (user.isEmailVerified) {
      return res.status(400).json({ message: "Email is already verified" });
    }

    user.isEmailVerified = true;
    await user.save();

    return res
      .status(200)
      .json({ message: "Email verified successfully. You can now login." });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const validation = loginSchema.safeParse(req.body);

    if (!validation.success) {
      return res.status(400).json({
        message: "Invalid data",
        errors: validation.error.flatten(),
      });
    }

    const { email, password } = validation.data;

    const user = await User.findOne({ email: email });

    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    if (!user.isEmailVerified) {
      return res.status(403).json({ message: "Please verify your email" });
    }

    const { accessToken, refreshToken } = generateToken(
      user._id.toString(),
      user.role,
      user.tokenVersion,
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: ms("7d"),
    });

    return res.status(200).json({
      message: "Login successful",
      user: {
        _id: user._id,
        email: user.email,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twoFactorEnabled: user.twoFactorEnabled,
      },
      accessToken,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function refreshHandler(req: Request, res: Response) {
  try {
    const refreshToken = req.cookies?.refreshToken as string | undefined;

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token is missing" });
    }

    const payload = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET!,
    ) as {
      _id: string;
      tokenVersion: number;
    };

    const user = await User.findById(payload._id);

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: "Token invalid" });
    }

    const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
      generateToken(user._id.toString(), user.role, user.tokenVersion);

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: ms("7d"),
    });

    return res.status(200).json({
      message: "Token refreshed",
      accessToken: newAccessToken,
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function logoutHandler(req: Request, res: Response) {
  try {
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    });

    return res.status(200).json({
      message: "Logged out successfully",
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  try {
    const validation = forgotPasswordSchema.safeParse(req.body);

    if (!validation.success) {
      return res.status(400).json({
        message: "Invalid data",
        errors: validation.error.flatten(),
      });
    }

    const { email } = validation.data;

    const user = await User.findOne({ email: email });

    if (!user) {
      return res.status(200).json({
        message:
          "If an account with this email exists, we will send a reset link",
      });
    }

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto
      .createHash("sha256")
      .update(rawToken)
      .digest("hex");

    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);
    await user.save();

    const resetUrl = `${process.env.APP_URL}/auth/reset-password?token=${rawToken}`;

    await sendEmail(
      user.email,
      "Reset your password",
      `
      <p>Click on the link below to reset your password.</p>
      <a href=${resetUrl}>${resetUrl}</a>
      `,
    );

    return res.status(200).json({
      message:
        "If an account with this email exists, we will send a reset link",
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  try {
    const validation = resetPasswordSchema.safeParse(req.body);

    if (!validation.success) {
      return res.status(400).json({
        message: "Invalid data",
        errors: validation.error.flatten(),
      });
    }

    const { token, newPassword } = validation.data;

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      resetPasswordToken: tokenHash,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired reset token",
      });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);

    user.passwordHash = passwordHash;

    // Clear reset token fields
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    // Invalidate all refresh tokens
    user.tokenVersion += 1;

    await user.save();

    return res.status(200).json({
      message: "Password reset successfully",
    });
  } catch (err) {
    console.log(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
}
