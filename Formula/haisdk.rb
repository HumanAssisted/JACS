class Haisdk < Formula
  include Language::Python::Virtualenv

  desc "HAI SDK CLI for JACS registration and attestation workflows"
  homepage "https://github.com/HumanAssisted/haisdk"
  head "https://github.com/HumanAssisted/haisdk.git", branch: "main"
  license "MIT"

  depends_on "python@3.12"
  depends_on "httpx"
  depends_on "cryptography"

  def install
    python = Formula["python@3.12"].opt_bin/"python3.12"
    venv = virtualenv_create(libexec, python, system_site_packages: true)
    venv.pip_install buildpath/"python"
    bin.install_symlink libexec/"bin/haisdk"
  end

  test do
    assert_match "HAI SDK CLI", shell_output("#{bin}/haisdk --help")
  end
end
