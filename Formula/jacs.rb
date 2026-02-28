class Jacs < Formula
  desc "JSON Agent Communication Standard command-line interface"
  homepage "https://github.com/HumanAssisted/JACS"
  url "https://crates.io/api/v1/crates/jacs/0.8.0/download"
  sha256 "69fc8df97a6b6f70fb1f4dc3a2b9a95571bfe7bcf6b8f6ba3c002f8be5a8886d"
  license "Apache-2.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args(path: "."), "--features", "cli", "--locked"
  end

  test do
    assert_match "jacs version: #{version}", shell_output("#{bin}/jacs version")
    assert_match "Usage: jacs [COMMAND]", shell_output("#{bin}/jacs --help")
  end
end
