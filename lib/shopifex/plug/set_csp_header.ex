defmodule Shopifex.Plug.SetCSPHeader do
  @moduledoc """
  Merges a `frame-ancestors` directive into the existing `content-security-policy`
  response header in order to securely load the embedded application in the
  Shopify admin panel.

  ## Merge behaviour

  Earlier plugs (e.g. Phoenix's `put_secure_browser_headers`) may already have
  set a `content-security-policy` header that includes important directives such
  as `script-src` and `connect-src`. This plug **merges** the required
  `frame-ancestors` value into that header rather than replacing it wholesale.

  The merge algorithm:

  1. Read the existing `content-security-policy` header (if any).
  2. Strip any pre-existing `frame-ancestors` directive from it.
  3. Append the new `frame-ancestors` directive.
  4. Write the result back as a single `content-security-policy` header.

  This ensures the final header satisfies both requirements simultaneously:

  - `script-src 'self' https://cdn.shopify.com` — permits App Bridge to load
    from the Shopify CDN (required for `<s-app-nav>`, `<s-link>`, `<ui-title-bar>`
    to register as custom elements).
  - `frame-ancestors https://admin.shopify.com https://<shop>.myshopify.com` —
    restricts iframe embedding to the Shopify Admin only.

  Read more: https://shopify.dev/apps/store/security/iframe-protection#embedded-apps
  """

  @shopify_unified_admin_url "https://admin.shopify.com"

  @spec init(options :: Plug.opts()) :: Plug.opts()
  def init(options), do: options

  @spec call(conn :: Plug.Conn.t(), opts :: Plug.opts()) :: Plug.Conn.t()
  def call(conn, _opts) do
    frame_ancestors = build_frame_ancestors(conn)
    existing_csp = get_existing_csp(conn)
    merged_csp = merge_frame_ancestors(existing_csp, frame_ancestors)

    Plug.Conn.put_resp_header(conn, "content-security-policy", merged_csp)
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp build_frame_ancestors(conn) do
    allowed =
      case get_current_shop(conn) do
        {:ok, shop} ->
          url = Shopifex.Shops.get_url(shop)
          [@shopify_unified_admin_url, "https://#{url}"]

        {:error, :no_current_shop} ->
          [@shopify_unified_admin_url]
      end

    Enum.join(allowed, " ")
  end

  # Returns the existing CSP string, or an empty string if none is set.
  defp get_existing_csp(conn) do
    case Plug.Conn.get_resp_header(conn, "content-security-policy") do
      [csp | _] -> csp
      [] -> ""
    end
  end

  # Strips any pre-existing frame-ancestors directive from `existing_csp`, then
  # appends the new `frame-ancestors` value. This guarantees exactly one
  # frame-ancestors directive in the final header and preserves all other
  # directives (script-src, connect-src, default-src, etc.) unchanged.
  defp merge_frame_ancestors(existing_csp, frame_ancestors_value) do
    directives_without_frame_ancestors =
      existing_csp
      |> String.split(";")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&String.starts_with?(&1, "frame-ancestors"))
      |> Enum.reject(&(&1 == ""))

    (directives_without_frame_ancestors ++ ["frame-ancestors #{frame_ancestors_value}"])
    |> Enum.join("; ")
    |> Kernel.<>(";")
  end

  defp get_current_shop(conn) do
    case Shopifex.Plug.current_shop(conn) do
      nil -> {:error, :no_current_shop}
      shop -> {:ok, shop}
    end
  end
end
