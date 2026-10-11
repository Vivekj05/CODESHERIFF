import type { Metadata } from "next";

import { Providers } from "@/components/providers";
import { ThemeProvider, ThemeScript } from "@/components/theme-provider";
import "./globals.css";

export const metadata: Metadata = {
  title: "CodeSheriff",
  description:
    "Security review for GitHub pull requests, with a probability you can check against ground truth.",
};

/**
 * Fonts come from @fontsource in globals.css (Manrope, Montserrat, Onest, Geist Mono), so nothing
 * here loads a font. Dark is the default; ThemeScript sets the class before first paint, which is
 * why <html> suppresses the hydration warning for its class list.
 */
export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="dark h-full" suppressHydrationWarning>
      <head>
        <ThemeScript />
      </head>
      <body className="min-h-full flex flex-col">
        <ThemeProvider>
          <Providers>{children}</Providers>
        </ThemeProvider>
      </body>
    </html>
  );
}
