import { z } from "zod";

const emailSchema = z.email().toLowerCase().trim();

const strongPasswordSchema = z
  .string()
  .trim()
  .min(8, { error: "Password must be at least 8 characters" })
  .max(100, { error: "Password must be at most 100 characters" })
  .regex(/[A-Z]/, { error: "Must include at least one uppercase letter" })
  .regex(/[a-z]/, { error: "Must include at least one lowercase letter" })
  .regex(/[0-9]/, { error: "Must include at least one number" })
  .regex(/[^A-Za-z0-9]/, {
    error: "Must include at least one special character",
  });

export const registerSchema = z.object({
  email: emailSchema,
  password: strongPasswordSchema,
  name: z
    .string()
    .trim()
    .min(3, { error: "Name must be at least 3 characters" })
    .max(50, { error: "Name must be at most 50 characters" }),
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z
    .string()
    .trim()
    .min(8, { error: "Password must be at least 8 characters" }),
});

export const forgotPasswordSchema = z.object({
  email: emailSchema,
});

export const resetPasswordSchema = z
  .object({
    token: z
      .string()
      .regex(/^[a-f0-9]{64}$/, { error: "Invalid token format" }),
    newPassword: strongPasswordSchema,
    confirmPassword: z.string().trim(),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    error: "Passwords do not match",
    path: ["confirmPassword"],
  });
