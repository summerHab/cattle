

package com.auth.common.core.util;

import com.auth.common.core.constant.ResultConstants;
import lombok.*;
import lombok.experimental.Accessors;
import java.io.Serializable;

/**
 * 响应信息主体
 * @param <T>
 * @author
 */
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Accessors(chain = true)
public class R<T> implements Serializable {

	private static final long serialVersionUID = 1L;

	@Getter
	@Setter
	private int code;

	@Getter
	@Setter
	private String msg;

	@Getter
	@Setter
	private T data;

	public static <T> R<T> ok() {
		return restResult(null, ResultConstants.SUCCESS, null);
	}

	public static <T> R<T> ok(T data) {
		return restResult(data, ResultConstants.SUCCESS, null);
	}

	public static <T> R<T> ok(T data, String msg) {
		return restResult(data, ResultConstants.SUCCESS, msg);
	}

	public static <T> R<T> failed() {
		return restResult(null, ResultConstants.FAIL, null);
	}

	public static <T> R<T> failed(String msg) {
		return restResult(null, ResultConstants.FAIL, msg);
	}

	public static <T> R<T> failed(T data) {
		return restResult(data, ResultConstants.FAIL, null);
	}

	public static <T> R<T> failed(T data, String msg) {
		return restResult(data, ResultConstants.FAIL, msg);
	}

	public static <T> R<T> restResult(T data, int code, String msg) {
		R<T> apiResult = new R<>();
		apiResult.setCode(code);
		apiResult.setData(data);
		apiResult.setMsg(msg);
		return apiResult;
	}

}
