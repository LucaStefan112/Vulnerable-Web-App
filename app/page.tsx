import Link from "next/link";

export default function Home() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 font-sans dark:bg-black">
      <main className="flex min-h-screen w-full max-w-3xl flex-col items-center justify-center gap-8 py-32 px-16 bg-white dark:bg-black">
        <div className="flex flex-col items-center gap-6 text-center">
          <h1 className="text-4xl font-bold leading-tight text-black dark:text-zinc-50">
            SecureNotes
          </h1>
          <p className="max-w-md text-lg leading-8 text-zinc-600 dark:text-zinc-400">
            An intentionally vulnerable note-taking application for security research and education.
          </p>
          <div className="mt-4 rounded-lg bg-yellow-50 border border-yellow-200 p-4 dark:bg-yellow-900/20 dark:border-yellow-800">
            <p className="text-sm text-yellow-800 dark:text-yellow-200">
              ⚠️ <strong>WARNING:</strong> This application contains intentional security vulnerabilities. 
              Do not use in production or expose to the public internet.
            </p>
          </div>
        </div>
        <div className="flex flex-col gap-4 text-base font-medium sm:flex-row">
          <Link
            href="/login"
            className="flex h-12 w-full items-center justify-center gap-2 rounded-full bg-zinc-900 px-5 text-white transition-colors hover:bg-zinc-800 dark:bg-zinc-50 dark:text-zinc-900 dark:hover:bg-zinc-200 md:w-[158px]"
          >
            Sign In
          </Link>
          <Link
            href="/register"
            className="flex h-12 w-full items-center justify-center rounded-full border border-solid border-zinc-300 px-5 transition-colors hover:border-transparent hover:bg-zinc-100 dark:border-zinc-700 dark:hover:bg-zinc-800 md:w-[158px]"
          >
            Register
          </Link>
        </div>
      </main>
    </div>
  );
}
