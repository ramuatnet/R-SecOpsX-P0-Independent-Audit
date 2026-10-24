# -*- coding: utf-8 -*-
r"""G7 language arms (2026-10-23): Ruby and Solidity detection.

Red-first: every positive below was observed failing before scanner/sast.py
gained the rules -- Ruby had exactly ONE rule (RUBY_RAILS_SECRET_TOKEN) and
Solidity had no extension mapping at all, so ``.sol`` never reached the
rule loop.

Ruby ships the direct-source shapes only (same honesty bar as
PHP_RAW_ECHO_XSS): request-derived input reaching a shell/exec sink, eval,
a SQL string built by interpolation, a file API taking params verbatim, an
ERB line that both touches request data and disables escaping, and
Marshal/YAML deserialisation of request or cookie data. Local-variable or
whitelisted equivalents stay dark.

Solidity ships three provable shapes: tx.origin in an authorization
comparison (origin confusion), a randomness variable fed from block
attributes, and a low-level call whose boolean result is discarded (bare
statement, not assigned or required). ``payable(x).call(...)`` receivers
with parentheses are outside the shipped sub-shape for SOL_UNCHECKED_CALL
and are documented as such, not faked.
"""
import textwrap


def _write(tmp_path, name: str, source: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return path


def _sast(tmp_path, name: str, source: str) -> list[dict]:
    from scanner.sast import scan_file

    return scan_file(str(_write(tmp_path, name, source)))


def _ids(findings: list[dict]) -> set[str]:
    return {str(f.get("rule_id") or f.get("id")) for f in findings}


# ---------------------------------------------------------------------------
# Ruby
# ---------------------------------------------------------------------------

def test_ruby_command_injection_interpolated_fires(tmp_path):
    findings = _sast(tmp_path, "list.rb", """\
        def index
          system("ls #{params[:dir]}")
        end
        """)
    assert "RUBY_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_ruby_command_injection_direct_params_fires(tmp_path):
    findings = _sast(tmp_path, "run.rb", """\
        def run
          spawn(params[:cmd])
        end
        """)
    assert "RUBY_CMD_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_ruby_command_whitelist_stays_dark(tmp_path):
    findings = _sast(tmp_path, "list.rb", """\
        ALLOWED = { "list" => "ls -la", "count" => "wc -l" }.freeze

        def index
          system(ALLOWED[params[:mode]])
        end
        """)
    # AL[...] is not a direct params->sink shape; the whitelist table is the
    # mitigation, and system() with a table value must not report.
    assert "RUBY_CMD_INJECTION" not in _ids(findings), sorted(_ids(findings))


def test_ruby_code_injection_eval_fires(tmp_path):
    findings = _sast(tmp_path, "expr.rb", """\
        def eval_rule
          eval(params[:expression])
        end
        """)
    assert "RUBY_CODE_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_ruby_eval_literal_stays_dark(tmp_path):
    findings = _sast(tmp_path, "expr.rb", """\
        def current_mode
          eval("Rails.env")
        end
        """)
    assert "RUBY_CODE_INJECTION" not in _ids(findings), sorted(_ids(findings))


def test_ruby_sql_interpolation_fires(tmp_path):
    findings = _sast(tmp_path, "search.rb", """\
        def search
          User.where("name LIKE '%#{params[:q]}%'")
        end
        """)
    assert "RUBY_SQL_INJECTION" in _ids(findings), sorted(_ids(findings))


def test_ruby_sql_placeholder_stays_dark(tmp_path):
    findings = _sast(tmp_path, "search.rb", """\
        def search
          User.where("name LIKE ?", "%#{params[:q]}%")
        end
        """)
    # Placeholder binding: the interpolation feeds the VALUE slot, not the
    # SQL text.
    assert "RUBY_SQL_INJECTION" not in _ids(findings), sorted(_ids(findings))


def test_ruby_path_traversal_send_file_fires(tmp_path):
    findings = _sast(tmp_path, "download.rb", """\
        def download
          send_file(params[:path])
        end
        """)
    assert "RUBY_PATH_TRAVERSAL" in _ids(findings), sorted(_ids(findings))


def test_ruby_path_constant_stays_dark(tmp_path):
    findings = _sast(tmp_path, "download.rb", """\
        def download
          send_file(Rails.root.join("public", "terms.pdf"))
        end
        """)
    assert "RUBY_PATH_TRAVERSAL" not in _ids(findings), sorted(_ids(findings))


def test_ruby_xss_raw_of_request_fires(tmp_path):
    findings = _sast(tmp_path, "show.html.erb", """\
        <h1><%= raw params[:comment] %></h1>
        """)
    assert "RUBY_XSS_ERB" in _ids(findings), sorted(_ids(findings))


def test_ruby_xss_plain_output_stays_dark(tmp_path):
    findings = _sast(tmp_path, "show.html.erb", """\
        <h1><%= @post.title %></h1>
        """)
    assert "RUBY_XSS_ERB" not in _ids(findings), sorted(_ids(findings))


def test_ruby_marshal_of_cookie_fires(tmp_path):
    findings = _sast(tmp_path, "session.rb", """\
        def restore
          Marshal.load(cookies[:state])
        end
        """)
    assert "RUBY_INSECURE_DESER" in _ids(findings), sorted(_ids(findings))


def test_ruby_marshal_of_local_stays_dark(tmp_path):
    findings = _sast(tmp_path, "session.rb", """\
        def restore
          Marshal.load(cached_payload)
        end
        """)
    assert "RUBY_INSECURE_DESER" not in _ids(findings), sorted(_ids(findings))


# ---------------------------------------------------------------------------
# Solidity
# ---------------------------------------------------------------------------

def test_solidity_tx_origin_authorization_fires(tmp_path):
    findings = _sast(tmp_path, "Vault.sol", """\
        pragma solidity ^0.8.0;

        contract Vault {
            function withdraw() external {
                require(tx.origin == owner, "not owner");
                payable(msg.sender).transfer(address(this).balance);
            }
        }
        """)
    assert "SOL_TX_ORIGIN_AUTH" in _ids(findings), sorted(_ids(findings))


def test_solidity_msg_sender_auth_stays_dark(tmp_path):
    findings = _sast(tmp_path, "Vault.sol", """\
        pragma solidity ^0.8.0;

        contract Vault {
            address public owner;

            function withdraw() external {
                require(msg.sender == owner, "not owner");
            }
        }
        """)
    assert "SOL_TX_ORIGIN_AUTH" not in _ids(findings), sorted(_ids(findings))


def test_solidity_block_randomness_fires(tmp_path):
    findings = _sast(tmp_path, "Lottery.sol", """\
        pragma solidity ^0.8.0;

        contract Lottery {
            function pick() external view returns (uint256) {
                uint256 winnerSeed = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender)));
                return winnerSeed % total;
            }
        }
        """)
    assert "SOL_WEAK_RANDOMNESS" in _ids(findings), sorted(_ids(findings))


def test_solidity_block_timestamp_deadline_stays_dark(tmp_path):
    findings = _sast(tmp_path, "Auction.sol", """\
        pragma solidity ^0.8.0;

        contract Auction {
            uint256 public endsAt;

            function bid() external {
                require(block.timestamp < endsAt, "auction closed");
            }
        }
        """)
    assert "SOL_WEAK_RANDOMNESS" not in _ids(findings), sorted(_ids(findings))


def test_solidity_unchecked_value_call_fires(tmp_path):
    findings = _sast(tmp_path, "Bank.sol", """\
        pragma solidity ^0.8.0;

        contract Bank {
            function payout(address payable to, uint256 amount) external {
                to.call{value: amount}("");
            }
        }
        """)
    assert "SOL_UNCHECKED_CALL" in _ids(findings), sorted(_ids(findings))


def test_solidity_required_call_result_stays_dark(tmp_path):
    findings = _sast(tmp_path, "Bank.sol", """\
        pragma solidity ^0.8.0;

        contract Bank {
            function payout(address payable to, uint256 amount) external {
                require(to.call{value: amount}(""), "transfer failed");
            }
        }
        """)
    assert "SOL_UNCHECKED_CALL" not in _ids(findings), sorted(_ids(findings))


def test_sol_extension_is_scannable(tmp_path):
    """`.sol` must reach the rule loop at all (LANG_BY_EXT + SCANNABLE_EXT)."""
    findings = _sast(tmp_path, "Access.sol", """\
        pragma solidity ^0.8.0;

        contract Access {
            function check() external view returns (bool) {
                return tx.origin == owner;
            }
        }
        """)
    assert "SOL_TX_ORIGIN_AUTH" in _ids(findings), sorted(_ids(findings))
