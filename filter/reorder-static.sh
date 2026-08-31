# shellcheck shell=sh disable=SC2006,SC2154

ngx_http_zstd_reorder_static_filter() {
    if ! echo " $HTTP_FILTER_MODULES " | grep " $next " >/dev/null; then
        echo "$0: error: cannot order $ngx_module_name before absent $next" >&2
        return 1
    fi

    HTTP_FILTER_MODULES=`echo " $HTTP_FILTER_MODULES " \
                         | sed "s/ $ngx_module_name / /" \
                         | sed "s/ $next / $next $ngx_module_name /" \
                         | sed "s/^ *//;s/ *\$//"`

    case " $HTTP_FILTER_MODULES " in
        *" $next $ngx_module_name "*) ;;
        *)
            echo "$0: error: failed to order $ngx_module_name after $next" >&2
            return 1
        ;;
    esac
}
