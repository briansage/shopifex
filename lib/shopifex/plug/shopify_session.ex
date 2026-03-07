defmodule Shopifex.Plug.ShopifySession do
  import Plug.Conn
  import Phoenix.Controller
  require Logger

  def init(options) do
    # initialize options
    options
  end

  def call(conn, _) do
    token = get_token_from_conn(conn) || Guardian.Plug.current_token(conn)

    case Shopifex.Guardian.resource_from_token(token) do
      {:ok, shop, claims} ->
        locale = get_locale(conn, claims)
        host = get_host(conn, claims)

        Shopifex.Plug.build_session(conn, shop, host, locale)

      _ ->
        initiate_new_session(conn)
    end
  end

  defp get_token_from_conn(%Plug.Conn{params: %{"token" => token}}), do: token

  defp get_token_from_conn(conn) do
    case Plug.Conn.get_req_header(conn, "authorization") do
      [] -> nil
      ["Bearer " <> token | []] -> token
      _ -> nil
    end
  end

  defp initiate_new_session(conn) do
    expected_hmac = Shopifex.Plug.build_hmac(conn)
    received_hmac = Shopifex.Plug.get_hmac(conn)

    if expected_hmac == received_hmac do
      conn
      |> do_new_session()
    else
      Logger.info("Invalid HMAC, expected #{expected_hmac}")
      respond_invalid(conn)
    end
  end

  defp do_new_session(conn = %{params: %{"shop" => shop_url}}) do
    case Shopifex.Shops.get_shop_by_url(shop_url) do
      nil ->
        redirect_to_install(conn, shop_url)

      shop ->
        locale = get_locale(conn)
        host = get_host(conn)

        Shopifex.Plug.build_session(conn, shop, host, locale)
    end
  end

  defp redirect_to_install(conn, shop_url) do
    Logger.info("Initiating shop installation for #{shop_url}")

    install_url =
      "https://#{shop_url}/admin/oauth/authorize?client_id=#{Application.fetch_env!(:shopifex, :api_key)}&scope=#{Application.fetch_env!(:shopifex, :scopes)}&redirect_uri=#{Application.fetch_env!(:shopifex, :redirect_uri)}"

    case conn.params do
      %{"embedded" => "1", "host" => _host} ->
        # The request is being rendered inside the Shopify admin iframe.
        # A bare 302 redirect cannot navigate the top-level window from inside
        # an iframe — we must use App Bridge to escape the iframe first.
        api_key = Application.fetch_env!(:shopifex, :api_key)

        conn
        |> put_resp_content_type("text/html")
        |> send_resp(200, iframe_escape_html(install_url, api_key))
        |> halt()

      _ ->
        # Not embedded — a normal top-level redirect is safe.
        conn
        |> redirect(external: install_url)
        |> halt()
    end
  end

  # Renders a minimal HTML page that uses App Bridge to escape the Shopify
  # admin iframe and redirect the top-level window to the OAuth grant screen.
  defp iframe_escape_html(redirect_url, api_key) do
    """
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="shopify-api-key" content="#{api_key}" />
      </head>
      <body>
        <script>
          document.addEventListener("DOMContentLoaded", function() {
            window.top.location.href = "#{redirect_url}";
          });
        </script>
        <p>Redirecting to install&hellip;</p>
      </body>
    </html>
    """
  end

  defp respond_invalid(%Plug.Conn{private: %{phoenix_format: "json"}} = conn) do
    conn
    |> put_status(:forbidden)
    |> put_view(ShopifexWeb.AuthView)
    |> render("403.json", message: "Unauthorized")
    |> halt()
  end

  defp respond_invalid(conn) do
    conn
    |> put_view(ShopifexWeb.AuthView)
    |> put_layout({ShopifexWeb.LayoutView, "app.html"})
    |> render("select-store.html")
    |> halt()
  end

  defp get_locale(conn, token_claims \\ %{})
  defp get_locale(%Plug.Conn{params: %{"locale" => locale}}, _token_claims), do: locale

  defp get_locale(_conn, token_claims),
    do: Map.get(token_claims, "loc", Application.get_env(:shopifex, :default_locale, "en"))

  defp get_host(conn, token_claims \\ %{})
  defp get_host(%Plug.Conn{params: %{"host" => host}}, _token_claims), do: host

  defp get_host(_conn, token_claims),
    do: Map.get(token_claims, "host")
end
