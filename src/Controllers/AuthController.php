<?php

namespace LittleSkin\YggdrasilConnect\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use LittleSkin\YggdrasilConnect\Exceptions\Yggdrasil\ForbiddenOperationException;
use LittleSkin\YggdrasilConnect\Exceptions\Yggdrasil\IllegalArgumentException;
use LittleSkin\YggdrasilConnect\Models\AccessToken;
use LittleSkin\YggdrasilConnect\Models\Profile;
use LittleSkin\YggdrasilConnect\Models\User;
use LittleSkin\YggdrasilConnect\Models\UUID;
use Ramsey\Uuid\Uuid as RamseyUuid;

class AuthController extends Controller
{
    public function authenticate(Request $request): JsonResponse
    {
        $identification = $request->input('username');

        /** @var User */
        $user = auth()->user();
        $uid = $user->uid;

        // clientToken 原样返回，如果没提供就给客户端生成一个
        $clientToken = $request->input('clientToken', RamseyUuid::uuid4()->getHex()->toString());

        $availableProfiles = Profile::getAvailableProfiles($user);

        if (empty($availableProfiles)) {
            Log::channel('ygg')->info("User [$uid] has no available profiles");

            throw new ForbiddenOperationException(
                trans('LittleSkin\\YggdrasilConnect::exceptions.user.no-available-profiles')
            );
        }

        $resp = [
            'accessToken' => '',
            'clientToken' => $clientToken,
        ];

        if ($request->input('requestUser')) {
            $resp['user'] = [
                'id' => User::getUserUuid($user),
                'properties' => [],
            ];
        }

        if (!filter_var($identification, FILTER_VALIDATE_EMAIL)) {
            $resp['selectedProfile'] = [
                'id' => Profile::getUuidFromName($identification),
                'name' => $identification,
            ];

            $resp['availableProfiles'] = [$resp['selectedProfile']];
        } elseif (count($availableProfiles) === 1) {
            $resp['selectedProfile'] = $availableProfiles[0];
            $resp['availableProfiles'] = [$availableProfiles[0]];
        } else {
            $resp['availableProfiles'] = $availableProfiles;
        }

        $accessToken = AccessToken::create($user);

        if (!empty($resp['selectedProfile'])) {
            $accessToken = $accessToken->refresh($resp['selectedProfile']['id']);
        }

        $resp['accessToken'] = $accessToken->jwt;

        Log::channel('ygg')->info(
            "New access token [$accessToken->jwt] generated for user [$uid]"
        );

        Log::channel('ygg')->info(
            "User [$uid] authenticated successfully",
            [compact('availableProfiles')]
        );

        ygg_log([
            'action' => 'authenticate',
            'user_id' => $user->uid,
            'parameters' => json_encode(
                $request->except('username', 'password')
            ),
        ]);

        return json($resp);
    }

    public function refresh(Request $request): JsonResponse
    {
        if (!method_exists(Validator::class, 'validateRequiredArrayKeys')) {
            Validator::extend('required_array_keys', function ($attribute, $value, $parameters) {
                if (!is_array($value)) {
                    return false;
                }

                foreach ($parameters as $param) {
                    if (!Arr::exists($value, $param)) {
                        return false;
                    }
                }

                return true;
            });
        }

        $validation = Validator::make($request->all(), [
            'selectedProfile' => ['nullable', 'required_array_keys:id,name'],
            'selectedProfile.id' => ['required_with:selectedProfile', 'string'],
            'selectedProfile.name' => ['required_with:selectedProfile', 'string'],
        ]);

        if ($validation->fails()) {
            throw new IllegalArgumentException(
                trans('LittleSkin\\YggdrasilConnect::exceptions.illegal')
            );
        }

        $clientToken = $request->input(
            'clientToken',
            RamseyUuid::uuid4()->getHex()->toString()
        );

        /** @var User */
        $user = auth()->user();

        $accessTokenToBeRefreshed = $user->yggdrasilToken();

        Log::channel('ygg')->info(
            "Try to refresh access token [$accessTokenToBeRefreshed->jwt] with client token [$clientToken]"
        );

        Log::channel('ygg')->info(
            "The given access token is owned by user [$user->uid]"
        );

        $selectedProfile =
            $request->input('selectedProfile.id')
            ?? $accessTokenToBeRefreshed->selectedProfile;

        $newAccessToken = $accessTokenToBeRefreshed->refresh($selectedProfile);

        Log::channel('ygg')->info(
            "New token [$newAccessToken->jwt] generated for user [$user->uid]"
        );

        $accessTokenToBeRefreshed->revoke();

        Log::channel('ygg')->info(
            "The old access token [$accessTokenToBeRefreshed->jwt] is now revoked"
        );

        Log::channel('ygg')->info(
            "Access token refreshed [$accessTokenToBeRefreshed->jwt] => [$newAccessToken->jwt]"
        );

        $profile = [
            'id' => $selectedProfile,
            'name' => UUID::where('uuid', $selectedProfile)
                ->first()
                ->player
                ->name,
        ];

        ygg_log([
            'action' => 'refresh',
            'user_id' => $user->uid,
            'parameters' => json_encode($request->except('accessToken')),
        ]);

        $resp = [
            'accessToken' => $newAccessToken->jwt,
            'clientToken' => $clientToken,
            'selectedProfile' => $profile,
            'availableProfiles' => [$profile],
        ];

        if ($request->input('requestUser')) {
            $resp['user'] = [
                'id' => User::getUserUuid($user),
                'properties' => [],
            ];
        }

        return json($resp);
    }

    public function validate(Request $request): Response|JsonResponse
    {
        ygg_log([
            'action' => 'validate',
            'user_id' => auth()->user()->uid,
            'parameters' => json_encode($request->except('accessToken')),
        ]);

        return response()->noContent();
    }

    public function signout(Request $request): Response
    {
        $user = $request->user();

        Log::channel('ygg')->info(
            "User [$user->uid] is try to signout"
        );

        AccessToken::revokeAllForUser($user);

        Log::channel('ygg')->info(
            "User [$user->uid] signed out, all tokens revoked"
        );

        ygg_log([
            'action' => 'signout',
            'user_id' => $user->uid,
        ]);

        return response()->noContent();
    }

    public function invalidate(Request $request): Response
    {
        /** @var User */
        $user = auth()->user();

        $token = $user->yggdrasilToken();
        $jwt = $token->jwt;

        Log::channel('ygg')->info(
            'Try to invalidate an access token',
            [$jwt]
        );

        $token->revoke();

        ygg_log([
            'action' => 'invalidate',
            'user_id' => $token->owner->uid,
            'parameters' => json_encode($request->json()->all()),
        ]);

        Log::channel('ygg')->info(
            "Access token [$jwt] was successfully revoked"
        );

        return response()->noContent();
    }
}