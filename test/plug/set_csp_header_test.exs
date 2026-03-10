defmodule Shopifex.Plug.SetCSPHeaderTest do
  use ShopifexWeb.ConnCase, async: true
  alias Shopifex.Plug.SetCSPHeader

  # ---------------------------------------------------------------------------
  # Helper — build a conn that already has a CSP header set (simulating the
  # :browser pipeline's put_secure_browser_headers running first).
  # ---------------------------------------------------------------------------

  defp with_existing_csp(conn, csp) do
    Plug.Conn.put_resp_header(conn, "content-security-policy", csp)
  end

  # ---------------------------------------------------------------------------
  # With shop session present — SetCSPHeader must MERGE frame-ancestors into
  # whatever CSP was already set by put_secure_browser_headers, NOT replace it.
  # ---------------------------------------------------------------------------

  describe "with shop session present in conn" do
    setup [:shop_in_session]

    test "adds frame-ancestors to an existing CSP set by put_secure_browser_headers", %{
      conn: conn
    } do
      existing_csp =
        "default-src 'self'; script-src 'self' https://cdn.shopify.com; connect-src 'self' https://cdn.shopify.com;"

      conn =
        conn
        |> with_existing_csp(existing_csp)
        |> SetCSPHeader.call([])

      [csp] = Plug.Conn.get_resp_header(conn, "content-security-policy")

      assert csp =~ "frame-ancestors https://admin.shopify.com https://shopifex.myshopify.com"
    end

    test "preserves script-src directive when merging frame-ancestors", %{conn: conn} do
      existing_csp =
        "default-src 'self'; script-src 'self' https://cdn.shopify.com; connect-src 'self' https://cdn.shopify.com;"

      conn =
        conn
        |> with_existing_csp(existing_csp)
        |> SetCSPHeader.call([])

      [csp] = Plug.Conn.get_resp_header(conn, "content-security-policy")

      assert csp =~ "script-src 'self' https://cdn.shopify.com"
    end

    test "preserves connect-src directive when merging frame-ancestors", %{conn: conn} do
      existing_csp =
        "default-src 'self'; script-src 'self' https://cdn.shopify.com; connect-src 'self' https://cdn.shopify.com;"

      conn =
        conn
        |> with_existing_csp(existing_csp)
        |> SetCSPHeader.call([])

      [csp] = Plug.Conn.get_resp_header(conn, "content-security-policy")

      assert csp =~ "connect-src 'self' https://cdn.shopify.com"
    end

    test "preserves default-src directive when merging frame-ancestors", %{conn: conn} do
      existing_csp =
        "default-src 'self'; script-src 'self' https://cdn.shopify.com; connect-src 'self' https://cdn.shopify.com;"

      conn =
        conn
        |> with_existing_csp(existing_csp)
        |> SetCSPHeader.call([])

      [csp] = Plug.Conn.get_resp_header(conn, "content-security-policy")

      assert csp =~ "default-src 'self'"
    end

    test "includes the shop's myshopify domain in frame-ancestors", %{conn: conn} do
      conn =
        conn
        |> with_existing_csp("default-src 'self';")
        |> SetCSPHeader.call([])

      [csp] = Plug.Conn.get_resp_header(conn, "content-security-policy")

      assert csp =~ "https://shopifex.myshopify.com"
    end

    test "always includes https://admin.shopify.com in frame-ancestors", %{conn: conn} do
      conn =
        conn
        |> with_existing_csp("default-src 'self';")
        |> SetCSPHeader.call([])

      [csp] = Plug.Conn.get_resp_header(conn, "content-security-policy")

      assert csp =~ "https://admin.shopify.com"
    end

    test "works when there is no existing CSP header (sets frame-ancestors only)", %{conn: conn} do
      conn = SetCSPHeader.call(conn, [])

      [csp] = Plug.Conn.get_resp_header(conn, "content-security-policy")

      assert csp =~ "frame-ancestors https://admin.shopify.com https://shopifex.myshopify.com"
    end

    test "replaces an existing frame-ancestors directive rather than duplicating it", %{
      conn: conn
    } do
      existing_csp =
        "default-src 'self'; frame-ancestors https://old-domain.example.com;"

      conn =
        conn
        |> with_existing_csp(existing_csp)
        |> SetCSPHeader.call([])

      [csp] = Plug.Conn.get_resp_header(conn, "content-security-policy")

      # The new frame-ancestors must be present
      assert csp =~ "frame-ancestors https://admin.shopify.com"
      # The old value must not survive
      refute csp =~ "https://old-domain.example.com"
    end

    test "produces exactly one content-security-policy header (no duplicates)", %{conn: conn} do
      conn =
        conn
        |> with_existing_csp("default-src 'self';")
        |> SetCSPHeader.call([])

      headers = Plug.Conn.get_resp_header(conn, "content-security-policy")
      assert length(headers) == 1
    end
  end

  # ---------------------------------------------------------------------------
  # Without shop session — falls back to admin.shopify.com only in frame-ancestors
  # ---------------------------------------------------------------------------

  describe "no shop session present in conn" do
    test "sets frame-ancestors to admin.shopify.com only when no shop in session", %{conn: conn} do
      conn =
        conn
        |> with_existing_csp("default-src 'self'; script-src 'self' https://cdn.shopify.com;")
        |> SetCSPHeader.call([])

      [csp] = Plug.Conn.get_resp_header(conn, "content-security-policy")

      assert csp =~ "frame-ancestors https://admin.shopify.com"
      refute csp =~ "myshopify.com"
    end

    test "preserves script-src even with no shop in session", %{conn: conn} do
      conn =
        conn
        |> with_existing_csp("default-src 'self'; script-src 'self' https://cdn.shopify.com;")
        |> SetCSPHeader.call([])

      [csp] = Plug.Conn.get_resp_header(conn, "content-security-policy")

      assert csp =~ "script-src 'self' https://cdn.shopify.com"
    end

    test "produces exactly one content-security-policy header with no shop in session", %{
      conn: conn
    } do
      conn =
        conn
        |> with_existing_csp("default-src 'self';")
        |> SetCSPHeader.call([])

      headers = Plug.Conn.get_resp_header(conn, "content-security-policy")
      assert length(headers) == 1
    end
  end
end
