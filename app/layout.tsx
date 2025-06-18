import type { Metadata } from "next";
import { Poppins } from "next/font/google";
import "./globals.css";

const poppins = Poppins({ subsets: ["latin"], weight: ["100", "200", "400", "700", '900'] });

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/logo.svg" sizes="any" />
      </head>
      <body className={`${poppins.className}`}>
        {children}
      </body>
    </html>
  );
}


// Change this data with your own 🤭
export const metadata: Metadata = {
  title: {
    default: 'Atzin Escandia ✷ Portfolio',
    template: '%s - Atzin Escandia',
  },
  description:
    'A customizable portfolio template for frontend developers, created by Atzin Escandia. Showcase your skills, projects, and experience with a clean and modern design.',
  icons: {
    icon: './favicon.ico',
  },
  applicationName: 'Frontend Portfolio Template by Atzin Escandia',
  authors: [
    {
      name: 'Atzin Escandia',
      url: 'https://www.linkedin.com/in/atzin-escandia/',
    },
  ],
  generator: 'Next.js',
  referrer: 'origin',
  themeColor: '#120012',
  colorScheme: 'dark',
  viewport: 'width=device-width, initial-scale=1',
  creator: 'Atzin Escandia',
  publisher: 'Atzin Escandia',
};
