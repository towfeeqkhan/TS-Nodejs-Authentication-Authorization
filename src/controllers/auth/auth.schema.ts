import { z } from "zod";

export const registerSchema = z.object({
  email: z.email().toLowerCase().trim(),
  password: z.string().min(6),
  name: z.string().min(3).trim(),
});

export const loginSchema = z.object({
  email: z.email().toLowerCase().trim(),
  password: z.string().min(6),
});

export const forgotPasswordSchema = z.object({
  email: z.email().toLowerCase().trim(),
});
