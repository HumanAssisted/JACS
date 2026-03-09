class Jacs < Formula
  desc "JSON Agent Communication Standard command-line interface"
  homepage "https://github.com/HumanAssisted/JACS"
  url "https://crates.io/api/v1/crates/jacs/0.9.0/download"
  sha256 "95a002c440eeea1fbd750b4521d3628751ae535fd51a9765e1a97f5ccd9dd8c1"
  license "Apache-2.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "jacs-cli")
  end

  test do
    assert_match "jacs version: #{version}", shell_output("#{bin}/jacs version")
    assert_match "Usage: jacs [COMMAND]", shell_output("#{bin}/jacs --help")
  end
end
