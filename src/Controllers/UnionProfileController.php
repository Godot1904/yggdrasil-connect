<?php

namespace LittleSkin\YggdrasilConnect\Controllers;

use GuzzleHttp\Client;
use GuzzleHttp\Promise;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use LittleSkin\YggdrasilConnect\Models\Profile;

class UnionProfileController extends Controller
{
    public function render(Request $request)
    {
        $apiRoot = rtrim((string) option('union_api_root'), '/');
        $servers = json_decode((string) option('union_server_list'), true);
        if (!is_array($servers)) {
            $servers = [];
        }

        if ($apiRoot === '') {
            return view('LittleSkin\\YggdrasilConnect::union', [
                'profiles' => [],
                'servers' => $servers,
                'union_api_root' => '',
            ]);
        }

        $players = auth()->user()->players->values();
        $promisesDup = [];
        $promisesSelf = [];
        $client = new Client([
            'timeout' => 5.0,
            'headers' => ['X-Union-Member-Key' => option('union_member_key')],
        ]);

        foreach ($players as $player) {
            $profile = Profile::createFromPlayer($player);
            $promisesDup[] = $client->requestAsync(
                'GET',
                $apiRoot.'/profile/unmapped/byname/'.rawurlencode($profile->name)
            );
            $promisesSelf[] = $client->requestAsync(
                'GET',
                $apiRoot.'/profile/detail/'.$profile->uuid
            );
        }

        $settle = class_exists(Promise\Utils::class)
            ? [Promise\Utils::class, 'settle']
            : 'GuzzleHttp\Promise\settle';

        $settledDup = $settle($promisesDup)->wait();
        $settledSelf = $settle($promisesSelf)->wait();

        $profiles = [];
        foreach ($players as $key => $player) {
            $selfResult = $settledSelf[$key] ?? null;
            if ($selfResult === null || $selfResult['state'] !== 'fulfilled') {
                Log::channel('ygg')->info(
                    "Union profile fetch failed for player [{$player->name}]."
                );
                continue;
            }

            $self = json_decode((string) $selfResult['value']->getBody(), true);
            if (!is_array($self)) {
                continue;
            }

            $dup = [];
            $dupResult = $settledDup[$key] ?? null;
            if ($dupResult !== null && $dupResult['state'] === 'fulfilled') {
                $decoded = json_decode((string) $dupResult['value']->getBody(), true);
                if (is_array($decoded)) {
                    $dup = $decoded;
                }
            }

            $profiles[] = [
                'self' => $self,
                'dup_name' => collect($dup)
                    ->keyBy('internal_id')
                    ->except($self['internal_id'] ?? null)
                    ->diffKeys(collect($self['bind'] ?? [])->keyBy('internal_id')),
            ];
        }

        return view('LittleSkin\\YggdrasilConnect::union', [
            'profiles' => $profiles,
            'servers' => $servers,
            'union_api_root' => $apiRoot,
        ]);
    }

    public function bind(Request $request)
    {
        $response = Http::timeout(5.0)
            ->withHeaders(['X-Union-Member-Key' => option('union_member_key')])
            ->post($this->apiRoot().'/profile/bind', ['uuid' => $request->input('uuid')]);

        if ($response->ok()) {
            $token = $response->json('token');
            if (is_string($token) && $token !== '') {
                return ['token' => $token];
            }

            return response()->json(['message' => 'Union did not return a token.'], 502);
        }

        return response($response->body(), $response->status())
            ->header('Content-Type', $response->header('Content-Type') ?: 'application/json');
    }

    public function unbind(Request $request)
    {
        $response = Http::timeout(5.0)
            ->withHeaders(['X-Union-Member-Key' => option('union_member_key')])
            ->post($this->apiRoot().'/profile/unbind', ['uuid' => $request->input('uuid')]);

        if ($response->ok()) {
            return;
        }

        return response($response->body(), $response->status())
            ->header('Content-Type', $response->header('Content-Type') ?: 'application/json');
    }

    public function bindTo(Request $request)
    {
        $response = Http::timeout(5.0)
            ->withHeaders(['X-Union-Member-Key' => option('union_member_key')])
            ->post($this->apiRoot().'/profile/bindto', [
                'uuid' => $request->input('uuid'),
                'token' => $request->input('token'),
            ]);

        if ($response->ok()) {
            return;
        }

        return response($response->body(), $response->status())
            ->header('Content-Type', $response->header('Content-Type') ?: 'application/json');
    }

    public function requestRemapUUID(Request $request)
    {
        $response = Http::timeout(5.0)
            ->withHeaders(['X-Union-Member-Key' => option('union_member_key')])
            ->post($this->apiRoot().'/profile/remapuuid', [
                'me' => $request->input('me'),
                'target' => $request->input('target'),
            ]);

        if ($response->ok()) {
            return;
        }

        return response($response->body(), $response->status())
            ->header('Content-Type', $response->header('Content-Type') ?: 'application/json');
    }

    private function apiRoot(): string
    {
        return rtrim((string) option('union_api_root'), '/');
    }
}
